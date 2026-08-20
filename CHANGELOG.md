# Changelog

All notable changes to acgs-lite will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Z3 policy strings are no longer evaluated as Python.** Policy text carried in
  constitution rules (`z3:` / `smt:` prefixes, `z3_expression` / `smt_constraint`
  metadata) was passed to `eval` with `{"__builtins__": {}}`. That construction
  blocks *name* lookup but not *attribute* lookup, and the eval locals held live
  z3 helpers, so `And.__globals__["__builtins__"]` reached a populated builtins
  mapping and a constitution rule could execute arbitrary code in the governed
  process. Policies are now parsed by an AST allowlist
  (`acgs_lite.formal.policy_ast`); attribute access, subscripting, lambdas,
  comprehensions, f-strings, dunder names, and calls to anything but
  `And`/`Or`/`Not`/`Implies` are rejected by construction. A malformed policy
  raises at decoration time instead of being skipped with a warning.
- **BREAKING: Z3 verification is fail-closed. `PASS` is the only status that
  permits execution.** The gate was `verified and not satisfiable` — block only
  on a *proven* violation — while every failure path set `verified=False`. A
  missing solver, a malformed policy, a timeout, or an exception therefore all
  read as "allow", and a one-character typo in a constitution silently turned a
  BLOCK into an ALLOW. `UNAVAILABLE`, `INVALID_POLICY`, `UNKNOWN`, and `ERROR`
  now block.
- **BREAKING: `INAPPLICABLE` blocks.** A policy naming none of a callable's
  parameters no longer permits the call. Policy variables are built from type
  hints, so a callable with no annotations binds nothing and is indistinguishable
  from one the policy genuinely does not concern — which made deleting an
  annotation a silent way out of a control. To run a callable that verification
  cannot clear, declare an exemption with
  `acgs_lite.verification_exempt(reason=..., approved_by=..., expires_at=...)`.
  Exemptions are per-callable, require attribution, expire within 365 days, are
  written to the audit chain on every use, and clear `INAPPLICABLE` only — never
  a proven violation, a malformed policy, a missing solver, or a solver error.
- **BREAKING: a Lean proof is not reported as proved unless the Lean kernel
  accepted it.** With no toolchain installed, `LeanstralVerifier` returned
  `proved=True` for LLM-generated proof text no kernel had read, and minted a
  `ProofCertificate` into the audit trail. It now returns `proved=False`,
  `certificate=None`, and exposes the candidate as `proposed_theorem` /
  `proposed_proof`.
- Formal verification remains optional, but its absence is now reported as
  `UNAVAILABLE` and blocks rather than silently disabling the layer. Install
  the solver with `pip install "acgs-lite[z3]"` (or `pip install z3-solver`).
  The `z3` extra is a declared optional dependency (`z3-solver>=4.12`) and is
  part of the aggregate `all` extra. CI verification lanes (`test`, `coverage`,
  `governance-regression`) install `.[dev,autonoma,anthropic,mcp,otel,z3]` so
  they exercise the same dependency set the published package offers. The
  `python-fallback` job stays z3-less — it is the lane that proves
  `UNAVAILABLE` blocks.
- **BREAKING: `acgs eval verify-constitution` can now fail, and its exit codes
  changed.** The command reported `satisfiable` / `contradiction` per CRITICAL
  rule, but `satisfiable` asserted a disjunction of fresh unconstrained booleans
  (independent of the rule) and `contradiction` required two rules sharing an `id`
  with different severities, which `Constitution` rejects at construction. Both
  columns were constants and the command always exited 0 — an assurance surface
  structurally incapable of detecting failure. It now verifies the `z3:` / `smt:`
  policies a constitution actually carries: each must parse, each must be
  individually satisfiable, and each variable-sharing cluster must be jointly
  satisfiable. Exit codes are a contract — `0` verified, `1` defect found, `2` not
  verified. **The no-argument invocation now exits 2**, because the built-in
  default constitution carries no policies and therefore verifies nothing; a
  command that verified nothing must not be indistinguishable from one that
  verified everything. New `--constitution FILE` verifies your own constitution; an
  unreadable path exits 2 (nothing was verified) while a file that loads but does
  not validate exits 1.
  Policy variables take the sort their syntax requires — `Bool` in a proposition
  position, `String` against a string literal, `Int` in a `%`, `Real` otherwise —
  matching what the runtime derives from `bool`/`str`/`int`/`float` annotations, so
  a policy the runtime can enforce is one this command can check. A policy that is
  *valid* rather than merely satisfiable (`Or(flag, Not(flag))`, `1 < 2`) exits 1:
  it constrains nothing, which is the defect class this command was an instance of.
  `VerificationResult` replaces `satisfiable`/`contradiction` with `status` from
  the same `VerificationStatus` vocabulary the runtime gate uses, and
  `NullVerificationGate` now reports `UNAVAILABLE` instead of a clean pass.
  (`Z3VerificationGate` is `experimental` in `docs/stability.md`.)

### Changed

- First-run path is now pip-only: README hero is a fail-closed 5-line snippet, and
  `docs/guides/five-minute-membrane.md` plus `examples/membrane_5min.py` show
  ALLOW / TRANSFORM / DENY / missing-receipt refusal. `pip install` does not
  ship `examples/`; the previous `pip install && python examples/...` command
  was unrunnable for a package-only install.
- Honesty pass: dropped the static tests-passing / star-history badges, labeled
  README compliance ratios as SELF-ASSESSED mapping coverage, and refreshed
  `GOAL.md` current-column facts for v2.12.0.

### Added

- Opt-in production execution grants: `GovernedCallable(..., authorization_profile="production")`
  rejects self-minted unsigned `DecisionReceipt` values. The executable tokens are a
  same-instance `ExecutionGrant` from `issue_grant()`, or a v2 execution-scope
  `SignedReceipt` whose envelope matches the current invocation and a pinned issuer
  key. Grants bind `module:qualname` plus a typed canonical argument digest.
  The default profile remains compatibility so existing receipt-passing callers
  keep working. In-process HMAC authenticity is process-scoped, not a
  distributed capability. Production `issue_grant()` mints single-use grants
  consumed by an in-process ledger: a second attempt id is rejected, the same
  attempt id recovers a completed result, an in-flight or failed attempt is
  not re-executed, and concurrent races admit exactly one winner. The ledger is
  not durable across processes. `DecisionReceipt` and `ExecutionBoundary` field
  schemas are unchanged. Grant IDs are still not a wire capability.

## [2.12.0] - 2026-08-15

### Added

- AMD GAIA adapter (`acgs_lite.integrations.gaia`): a duck-typed
  `PolicyEngine` plus checkpoint / receipt / policy-binding seams so
  GAIA can swap the in-repo tag stub for a constitution-backed engine.
  GAIA risk tags stay a floor; `GAIA_AUTO_APPROVE_TOOLS` is ignored;
  missing adapter surfaces fail closed. Local and tested; not a claim
  that AMD ships this by default.

### Fixed

- Corrected stale EU AI Act high-risk deadline claims (previously "August 2, 2026") across the
  library (`acgs_lite.eu_ai_act`, `acgs_lite.compliance.eu_ai_act`), the CLI (`acgs_lite.cli`,
  `acgs_lite.compliance.__main__`, `acgs_lite.commands.eu_ai_act`), generated Markdown/PDF
  reports (`acgs_lite.report`), project-scaffold templates (`acgs_lite.commands.init`), and docs
  (`docs/compliance-2026.md`). Per the 2026 Digital Omnibus deferral (Council final approval
  2026-06-29): Annex III stand-alone high-risk systems now must comply by 2027-12-02; Annex I
  embedded-product high-risk systems by 2028-08-02.

- Corrected numerous stale or fabricated regulatory citations and overclaiming language across
  the compliance framework modules (`acgs_lite.compliance.*`) and their examples/docs, surfaced
  by a multi-round adversarial legal-citation review. Highlights: EU AI Act Article 52 → 50 and
  Article 72 → 43 renumbering with correct Article 50(1)-(4) transparency sub-paragraph mapping;
  fundamental-rights impact assessment re-cited to Article 27(1) (was 26(9)); GPAI training-data
  summary duty corrected to Article 53(1)(d) (a fabricated Article 53(2) DB-registration duty
  removed); DORA article re-pairs across Articles 6, 8, 9, 12, 17, 19, 26, 28, and 30, including
  the real TLPT citation (Article 26(1), not 25) and a corrected penalty regime description;
  China AI Governance citation re-pairs across the Algorithm Recommendation, Deep Synthesis, and
  Generative AI Interim Measures articles, and a corrected (non-fabricated) CAC filing trigger for
  generative AI services; India DPDP Act section renumbering (notice, accuracy, security, breach,
  erasure, DPO/grievance contact, and Significant Data Fiduciary obligations moved to their
  correct sections); Canada AIDA and other framework `status` fields corrected to reflect real
  enactment state; the true supported-framework count corrected to 20 everywhere it was
  previously stated as 18 or 19; Singapore MAIGF item references reworded to a descriptive,
  non-numbered form after the specific PDPC sub-clause numbering could not be independently
  verified; and several silently-vacuous test assertions (empty-list `all()`/`any()` checks left
  behind by earlier reference renames) hardened to fail loudly instead of passing without
  exercising anything. Overclaiming language ("ensures," "mathematically proves," "immutable")
  was also reworded to accurate, verifiable claims ("supports," "tamper-evident," "detects")
  throughout the affected modules and documentation.

## [2.11.0] - 2026-07-28

### Security

- **BREAKING: `GovernedAgent` now enforces MACI fail-closed by default.** The
  default is `enforce_maci=True`; callers that use `GovernedAgent` must pass a
  `maci_role` at construction time and a `governance_action` for governed runs.
  Misconfigured or missing role/action context now fails closed instead of
  silently treating MACI as advisory.
- Added a bundled fail-closed Claude Code governance hook route so local hook
  enforcement no longer depends on an unbundled `/x402/check` sidecar.
- Closed adversarially proven fail-open paths in framework integrations,
  including delegated `__getattr__` calls, bytes-like and non-first positional
  code/task carriers, dict-keyed smolagents `step_callbacks`, unknown hook
  decision classes, and multi-governor wrapping gaps.
- Hardened validation and code-analysis failure behavior: validator crashes now
  fail closed, blocked CRITICAL decisions are retained in full-audit mode, and
  builtin-laundering / `__builtins__` escape vectors are blocked.
- Added an honest `SECURITY.md` responsible-disclosure policy with scope,
  supported-version posture, and response-window targets. It does not claim
  certification, production readiness, independent staffing, or third-party
  validation.

### Added

- Graduated the Runtime Legitimacy Kernel to a stable public surface, with
  receipt-bound legitimacy contracts documented as the committed membrane story.
- Added the governed execution membrane example and tests for the
  `request -> decision -> receipt -> bounded execution` positioning.
- Added a five-trigger adversarial fail-closed suite with committed evidence
  artifacts covering authorization, constitution version, policy staleness,
  receipt integrity, and audit-evidence verifiability.
- Added a CI governance-regression gate and invariant pinning so previously
  closed bypass vectors, the canonical constitutional hash, and receipt-binding
  assumptions are checked continuously.
- Added a real-LLM experiment harness backed by real `AuditLog` plumbing. This
  release includes the harness only; it does not include or claim empirical
  real-LLM results.
- Added Japan AI Guidelines for Business compliance mapping, Swarms governance
  adapter support, xAI/Grok adapter tests, smolagents adapter coverage, SMT
  boundary verification for governed callables, and a recruiting-domain
  constitution template.
- Added runnable examples and docs for DSPy governance, GitHub Actions,
  pre-commit usage, AI-agent verification, LangChain onboarding, integration
  choice guidance, and what-gets-blocked walkthroughs.
- Added `examples/release_proof.py`, a release-proof demo that runs without API
  keys and emits a deterministic JSON artifact for fresh-venv verification. The
  artifact reports the installed package version rather than a hardcoded one.
- Added `scripts/check_release_coherence.py`, a guard that fails when a version
  is presented as released in `CHANGELOG.md` but has no matching git tag.
- Added `scripts/check_links.py` and wired it into `make validate` and CI so
  broken repository and documentation links fail the build.
- Added an experimental `gove` extra (`acgs_lite.gove`, Python >= 3.11) bridging
  the gove-zone kernel through a `ConstitutionPolicy` adapter. Its receipt format
  is distinct from `legitimacy` and is not translated between the two.

### Changed

- Repositioned the project around the constitutional governance membrane:
  ACGS-Lite checks proposed side effects, emits decisions and receipts, and
  records audit evidence; it does not claim to be an agent framework or a
  compliance-certification layer.
- Completed the public honesty pass: removed unsupported social proof, avoided
  claims of independently confirmed production users, labeled simulations and
  self-assessed compliance coverage, and kept adoption claims limited to
  verifiable evidence.
- Updated smolagents documentation so fail-open/strict-flag behavior matches the
  implementation instead of overstating enforcement.
- Added measurable `GOAL.md` success criteria that separate buildable release
  work from owner-gated or third-party-gated outcomes such as PyPI token
  renewal, curated-list acceptance, independent adoption, and external
  validation.
- Refreshed planning, community, and capability-manifest docs, including Stage 0
  community scaffolding and Stage 1 ignition content.
- Updated Rust dependency pins for `spacetimedb`, `wasm-bindgen-test`, and
  `serde_json`.
- Migrated CI workflows to Blacksmith runners.
- Triaged the nltk CVE-2026-54293 advisory in `BLOCKERS.md`.

### Fixed

- Repaired constitution templates that failed to load and added a guard that
  every shipped template loads and enforces.
- Fixed hook and integration routing so every code/task carrier is gated, not
  just the first positional carrier.
- Pinned strict per-call override behavior against shared-state mutation and
  guarded heavy ML libraries against eager module-level imports.
- Fixed README audit example usage and the lending example load path in the
  constitutions README.
- Preserved distinct audit findings when validator errors occur.
- Capped the `mcp` extra at `mcp>=1.0,<2.0`. MCP SDK 2.0.0 removed
  `Server.list_tools`, which broke `integrations.mcp_server` against the
  previously unbounded `mcp>=1.0` requirement.
- Repaired 49 stale repository URLs that still pointed at the pre-transfer
  `dislovelhl/acgs-lite` path, and absolutized 28 relative README links so they
  resolve on the PyPI project page instead of 404ing.
- Populated the previously blank Security and Changelog documentation pages and
  enabled `check_paths` so `mkdocs build --strict` catches a recurrence.
- Fixed broken CHANGELOG version-compare links, an incorrect clone path, and an
  `acgs2.ai` domain typo; added the two missing GitHub issue templates.
- Corrected the advertised compliance-framework count to the 20 the registry
  actually holds, and fixed the test that passed only incidentally.

### Known limitations

- Simulations and seeded harness runs are not empirical benchmarks. The real-LLM
  experiment harness is present, but real artifacts require provider API keys,
  committed result JSON, stated datasets/sample sizes, and explicit summaries.
- There are no independently confirmed production users in this release.
- PyPI publication is performed by the `Publish to PyPI` workflow on a published
  GitHub Release, using PyPI trusted publishing. Creating that release remains an
  owner-gated action.
- Curated-list submission or acceptance, third-party validation, certification,
  and independent adoption remain external outcomes and are not claimed here.

## [2.10.1] - 2026-05-16

### Changed

- MCP server integration: documented the non-mutating `validate(strict=False)` contract.
  MCP tools (`validate_action`, `check_compliance`, `explain_violation`) pass `strict=False`
  per call and never touch `engine.strict`; concurrent callers and shared engines are
  unaffected. `engine.non_strict()` is still available but not recommended under concurrency.
- EU AI Act deadline wording: CLI output, init templates, compliance module, PDF/Markdown
  reports, and docs now use "main high-risk obligations: August 2, 2026" instead of the
  over-broad "enforcement" framing. Docs note that timeline adjustments may be proposed.
- Performance figures in README, architecture docstrings (`lean_verify.py`, `z3_verify.py`,
  `memoization.py`), and the integration dashboard replaced hardcoded latency numbers
  (`~443 ns`, `<10 ms`, etc.) with workload-dependent language.
- `docs/why-governance.md`: tightened MACI guarantee language from "no single compromised
  agent can bypass governance" to "no single compromised agent can both propose and approve
  its own actions" — reflects what MACI structurally enforces.
- `integrations/agno.py` example model updated to `gpt-5.4` (matches provider capability
  manifest; `gpt-5.4-mini` was not in the manifest).

### Fixed

- `tests/test_server_api_key_auth.py`: two fixtures now call
  `monkeypatch.delenv("ACGS_API_KEY", raising=False)` before constructing the app,
  preventing environment bleed when `ACGS_API_KEY` is already set in the parent process.

### Internal

- `.gitignore` hardened: `.agents/`, `.bt/`, `.env`, `.env.*` (excluding `.env.example`),
  and root-level `/*.pdf` assessment outputs are now excluded.

## 2.10.0 - 2026-04-23

### Breaking Changes

- **`create_governance_app(require_auth=...)` default flipped from `None` to `True`** (`server-secure-by-default` phase 2). The HTTP server now fails closed by default: calling `create_governance_app()` without an `api_key` / `ACGS_API_KEY` raises `ValueError`. To preserve the v2.9.x fail-open behaviour explicitly, pass `require_auth=None` (warns at startup) or `require_auth=False` (silent). Production deployments should set `api_key=...` or the `ACGS_API_KEY` environment variable.

### Added

- **`PostgresBundleStore`** (optional `postgres` extra): multi-instance-safe backend for the constitution lifecycle store. Mirrors the `BundleStore` Protocol with a partial unique index on `(tenant_id) WHERE status='active'` enforcing one-active-per-tenant at the database level, and `SELECT ... FOR UPDATE` serializing CAS updates. Install with `pip install 'acgs-lite[postgres]'`. SQLite remains the default single-host backend.
- **Rust wheel packaging** (`rust/pyo3/pyproject.toml` + `.github/workflows/wheels.yml`): the optional Rust accelerator now builds as a standalone `acgs-lite-rust` companion wheel via maturin. GitHub Actions produces abi3 wheels for manylinux (x86_64, aarch64), macOS (x86_64, arm64), and Windows (x64), plus an sdist, on `rust-v*` tag pushes. Users install with `pip install acgs-lite acgs-lite-rust` to opt into the hot-path speedup; `acgs-lite` itself remains pure-Python.
- **`examples/agent_quickstart/`**: Self-verifying AI-agent quickstart. Run `python examples/agent_quickstart/run.py` to confirm `GovernedCallable`, MACI role gates, and tamper-evident audit all work in a single script that exits 0. Designed as a copy-paste install-verification prompt for AI coding agents (Codex, Claude Code, and similar tools).
- CI: Python fallback job (`python-fallback`) runs the full test suite without the Rust companion installed — ensures the pure-Python path always works independently of the optional accelerator.
- CI: test matrix expanded to Python 3.10, 3.11, 3.12, and 3.13.

### Changed

- `validate()` now accepts a `strict` keyword argument for per-call strict override without mutating `engine.strict`. All built-in integrations use this pattern. `non_strict()` context manager remains available but is not recommended for async/concurrent use (thread-safety caveat documented in its docstring).
- `workflow.py` `GovernanceWorkflowExecutor` migrated to `with engine.non_strict()` context manager.
- `scoring.py` cold import reduced from ~3.5 s to ~218 ms by making the `transformers`/`torch` import lazy.
- `InMemoryTrajectoryStore` operations now use a `threading.RLock` — safe for concurrent agent use.

### Fixed

- Python 3.10 compatibility: `datetime.UTC` (3.11+) replaced with `timezone.utc` throughout; `StrEnum` polyfill added in `_compat.py`; `tomllib` falls back to `tomli` on 3.10.
- `PostgresBundleStore.load_bundles()` used `LIMIT NULL` (PostgreSQL syntax error) — fixed to `LIMIT ALL` when no limit is specified.
- `PostgresBundleStore._init_schema()` race on concurrent first-connection — fixed with `CREATE TABLE ... ON CONFLICT DO NOTHING` in the schema migrations insert.
- `PostgresBundleStore.save_bundle_transactional()` phantom-row CAS race — fixed with `pg_advisory_xact_lock(hashtext(%s)::bigint)` before `SELECT FOR UPDATE`.
- `FrequencyThresholdRule` reported the wrong `agent_id` (used raw list index instead of chronologically-sorted position) — fixed to read `agent_id` from the decision at the correct sorted position.
- `WebhookNotificationChannel` and `InterventionEngine` webhook callers now validate URL scheme (must be `http` or `https`) before calling `urlopen`, preventing SSRF via non-HTTP schemes.
- `SQLiteBundleStore.list_bundles()` used f-string interpolation for `LIMIT`/`OFFSET` — fixed to parameterized queries.

## [2.9.0] - 2026-04-22

### Upgrading from 2.8.1

No API changes. The `GovernanceEngine` core is stable. 

**One behavioral change to be aware of:** If you pass `audit_metadata` to `engine.validate()` in non-strict mode, audit entries are now written (previously, the Rust fast path silently dropped them). This is the correct behavior; if your benchmarks are sensitive to audit write overhead, see the `audit_metadata` parameter docs.

**PyPI stability classifier:** The package classifier changed from `5 - Production/Stable` to `4 - Beta`. This reflects the lifecycle API and newer integrations being Beta, not the core engine. See the Component Stability table in README.md — GovernanceEngine, MACI, AuditLog, and GovernedAgent remain Stable.

---

### Added

- **ARC-Kit bridge** (`acgs_lite.arckit`): parse architecture diagrams, generate and export
  constitution bundles, emit CLI commands, and map to compliance frameworks — full pipeline from
  project structure to governed rules.
- **Governance memory** (`constitution.governance_memory`): unified retrieval layer over rules and
  precedents; MCP `validate_action` tool now returns matched rules and precedents in the response.
- **Policy linter** (`constitution.policy_linter`): static quality analysis of YAML constitution
  files with structured findings and a CI-friendly exit code.
- **`GovernanceStream`**, **`PolicyStorage`**, and DI-scoped service interfaces for framework
  integration (AFFiNE-style architecture patterns).
- **Batch audit writes**: `AuditLog.record_atomic_many()` writes multiple entries atomically to
  durable backends, reducing round-trips for bulk governance events.
- 21 previously internal governance symbols exported from the public API.

### Upgrading from 2.8.1

No API changes. All existing code runs without modification. Two behavior changes worth noting:

- **`audit_metadata` is now written on non-strict fast paths** — callers that pass `audit_metadata`
  to `validate()` in non-strict mode previously had the metadata silently discarded on the Rust
  fast path. It is now written. If you rely on the fast-path throughput benefit, remove
  `audit_metadata` from non-strict calls or accept the ~10% throughput reduction.
- **`check_checkpoint()` is now serialized** — concurrent calls to the same `TrajectoryMonitor`
  instance are now queued. If you have highly concurrent checkpoint calls per monitor, benchmark
  the new behavior under load.

`GovernanceEngine`, `AuditLog`, and all stable-tier components are unaffected. See the Component
Stability table in the README for the stability tier of each subsystem.

### Changed

- PyPI development-status classifier changed from `5 - Production/Stable` to `4 - Beta`.
  This reflects the new subsystems added in 2.9.0 (ARC-Kit, GovernanceStream, lifecycle API,
  MCP server) which are still stabilizing. **Core rule validation, constitution loading, MACI
  enforcement, and audit logging remain `Stable`** — see the Component Stability table in README.
  Package description also rewritten for accuracy.
- README: added "Safety Defaults" section and "Component Stability" table.
- Rust fast path enabled for `strict=False` validation mode (+374% allow-ops throughput).

### Fixed

- **Telegram webhook** (`integrations.telegram_webhook`): handler changed from `async def` to
  `def` so FastAPI runs it in a thread pool and the event loop is not blocked by the synchronous
  `validate()` call.
- **MCP server strict-mode safety** (`integrations.mcp_server`): `engine.strict` is now restored
  inside a `try/finally` block at all three call sites so an exception during `validate()` cannot
  leave strict mode permanently disabled.
- `engine_getter` pattern in `create_telegram_webhook_router` prevents stale engine closure after
  `_rebuild_engine` replaces the module-level engine.
- CDP report generation: `fpdf2` API call updated (`ln=True` → `new_x`/`new_y`) for fpdf2 ≥ 2.8.
- PQC module now catches `SystemExit` and `RuntimeError` from broken oqs/liboqs installations
  instead of propagating them.
- `__init__.py` duplicate-import warnings (F811) removed.
- **Rust fast-path audit guard** (`engine/core.py`): the `strict=False` Rust fast path no longer
  fires when `audit_metadata` is provided. Previously, a caller that passed `audit_metadata` in
  non-strict mode would hit the fast path and have the metadata silently discarded — no audit
  entry written. The fast path is now bypassed when `audit_metadata` is present.
- **`TrajectoryMonitor` thread safety** (`trajectory.py`): `check_checkpoint()` is now
  serialized with a `threading.Lock`. Previously, concurrent calls from different agents sharing
  a `TrajectoryMonitor` instance had a read-modify-write race on the session store. Concurrent
  access is now safe.
- `AuditLog.record()` backend write serialized under state lock (thread-safety regression fix).
- `record_atomic` is now truly atomic for durable backends.

## [2.8.1] - 2026-04-16

### Changed (fail-closed hardening, non-breaking)

- **Streaming validator is now fail-closed on engine exception.** `StreamingValidator._validate_window` previously swallowed any engine exception and returned `passed=True, should_halt=False` — a silent fail-open that defeats constitutional guarantees when the engine is unstable. The default is now `passed=False, should_halt=True` with an `ERROR`-level log line. A new `fail_open_on_error: bool = False` constructor flag restores the legacy behavior for callers that genuinely need it. Existing test coverage was migrated to the explicit opt-in, and new tests pin the fail-closed default.
- **`StreamingValidator` now emits a `UserWarning` when `blocking_severities` is unset.** The empty-set default means no severity level halts the stream; this is a silent safety gap. Pass `blocking_severities={"critical"}` (or higher) to silence the warning. The default will change to `{"critical"}` in 3.0.
- **`GovernedAgent` emits a `DeprecationWarning` when `maci_role` is set but `enforce_maci=False`.** This is the most common misconfiguration surfaced by the v2.8 gap analysis — MACI role separation looks enforced but is advisory. The `enforce_maci` default will flip to `True` in 3.0. Opt in now with `enforce_maci=True` plus `governance_action=...` on every run.

### Added

- **Opt-in quarantine wiring in `InterventionEngine`.** New constructor parameter `quarantine: GovernanceQuarantine | None = None`. When supplied, the `ESCALATE` action submits the offending CDP record to quarantine (with `quarantine_id` surfaced on the outcome metadata) instead of only flagging `requires_review`. The previously orphan `GovernanceQuarantine` module is now reachable from the standard intervention pipeline without any API break — default `None` preserves v2.8.0 behavior.

### Fixed

- **Observable error handling in `GovernedAgent._emit_cdp`.** Three blanket `except Exception: pass` blocks (runtime compliance check, intervention handler, outer CDP emission) are replaced with logged `ERROR` entries including exception type and traceback. Fail-open semantics are preserved for CDP (the governed call never fails from CDP trouble), but failures are now diagnosable instead of silent. The inner `server`-backend import fallback is now logged at `DEBUG`.
- **Thread-safety for `AuditLog.record()`.** `AuditLog._entries` and `AuditLog._chain_hashes` are now protected by a `threading.Lock` during read-modify-write (chain hash computation, append, trim-on-overflow). The backend write is deliberately released outside the lock to avoid serializing all recorders on disk I/O. Eliminates the race where concurrent recorders could corrupt the chain hash.
- **Thread-safety for `InterventionEngine` throttle and cool-off state.** `_handle_throttle` and `_handle_cool_off` now take a `threading.Lock` around dict read-modify-write; `is_cooled_off` takes the lock for the read. Eliminates lost-update and torn-read bugs under concurrent evaluation.

### Deprecation notices

- `StreamingValidator(blocking_severities=None)` — default will change in 3.0.
- `GovernedAgent(maci_role=<role>, enforce_maci=False)` — default will flip in 3.0.

## 2.8.0 - 2026-04-15

### Added

- **Phase A — Real eval integration**: `ConstitutionLifecycle.run_evaluation()` now executes actual `EvalScenario` objects against a `GovernanceEngine` built from the bundle's constitution. Pass rate is recorded in `bundle.eval_summary`. Vacuous-pass bypass (empty/None scenarios) raises `LifecycleError`. Self-approval guard added to `approve()`.
- **Phase B — SQLite persistent BundleStore**: New `SQLiteBundleStore` survives process restarts. WAL journal mode, `BEGIN EXCLUSIVE` transactions for multi-step writes, and a partial unique index enforce one active bundle per tenant at the database level. Raw `sqlite3.OperationalError` is wrapped as `LifecycleError` with context.
- **Phase C — FastAPI lifecycle router**: Thirteen REST endpoints under `/constitution/lifecycle/` expose the full saga lifecycle (10 `POST` mutation endpoints + 3 `GET` read endpoints), including `POST /{id}/reject` for VALIDATOR-role rejection. When configured, all lifecycle endpoints require `X-API-Key` authentication. Pydantic request models provide OpenAPI schema. Active-bundle response includes `engine_binding_active: bool` to surface the Phase C/E gap explicitly.
- **Phase E — BundleAwareGovernanceEngine**: `BundleAwareGovernanceEngine(store).for_active_bundle(tenant_id)` returns a `GovernanceEngine` built from the tenant's active bundle constitution. Engine cache is keyed by `(tenant_id, bundle_hash)` with `threading.Lock`. Host applications must call `invalidate(tenant_id)` after lifecycle changes that should refresh the bound engine.
- **Agno integration adapter**: New `acgs_lite.integrations.agno` adapter for the Agno agent framework (optional `[agno]` extra).
- **`[server]` extra**: `fastapi` + `uvicorn` now installable as `pip install acgs-lite[server]` for the lifecycle HTTP router.
- **Lifecycle quickstart example**: `examples/lifecycle_quickstart.py` demonstrates the full `create_draft → run_evaluation → activate → validate()` flow end-to-end.
- **Lifecycle HTTP API docs**: `docs/api/lifecycle.md` documents all thirteen endpoints with request/response shapes, error codes, and auth requirements.
- **Audit trail parity in `withdraw()`**: `withdraw()` now passes `reason` to `status_history`, matching the audit record written by `reject()`. Both ops now leave a full operator-reason trail.

## [2.7.2] - 2026-04-09

### Fixed
- **Standalone package test compatibility**: Fixed four test files that used monorepo-relative
  `parents[3]` path calculations, updated to `parents[1]` (repo root). Added `skipif` guards
  for tests that require `autoresearch/` data not present in the standalone package
  (`test_autoresearch_scenario_corpus.py`, `test_real_use_case_datasets.py`,
  `test_rule_metrics.py`, `test_provider_capability_manifest.py`).
- **Editable install path**: Updated `.pth` file to point to `src/` in the standalone repo
  rather than the old monorepo location.

## 2.7.1 - 2026-04-09

### Added
- **Constitutional swarm mesh settlement durability**: `SQLiteSettlementStore` provides a
  persistent SQLite-backed settlement store alongside the existing `JSONLSettlementStore`.
  Mesh proofs now survive process restarts. Settlement backends implement a pluggable
  `SettlementStore` protocol; swap adapters at instantiation time.
- **Provider capabilities manifest and session observability**: `provider_capabilities.py`
  ships a `provider_capabilities_manifest.json` with validated model IDs and capability
  flags for all major providers. `observe_session.py` command enables live observation
  logging with structured JSONL output.
- **acgs-lite hardening**: circuit breaker, fail_closed, governed, scoring, and all
  integration adapters (openai, anthropic, langchain, litellm, autogen, pydantic_ai,
  google_genai, haystack) received audit and exception logging improvements.

### Fixed
- **JWT verification error no longer leaks exception details**: `auth.py` error handler
  now logs `type(e).__name__` only, not the full exception string, preventing token
  content or key material from appearing in logs.
- **GovernanceEngine `strict` flag leak**: `openai.py` integration wraps the temporary
  `strict=False` output validation in `try/finally`, guaranteeing the flag is always
  restored even if `validate()` raises. Concurrent callers can no longer observe a
  permanently-disabled strict mode.

### Changed
- **JWT algorithm normalization unified** across `enhanced_agent_bus`, `collaboration`,
  and `enterprise_sso`: all JWT decode paths now use `resolve_jwt_algorithm()` from
  `src.core.shared.security.jwt_algorithms`, enforcing a canonical allowlist of
  `{RS256, RS384, RS512, ES256, ES384, EdDSA, HS256}`.
- **CapabilityPassport tier routing hardened**: T030-T032 integration tests cover
  override, tamper fail-closed, and no-passport fallthrough scenarios.

## [2.7.0] - 2026-04-06

### Added
- **`ViolationAction` enum** (`src/acgs_lite/constitution/rule.py`): Replaces the
  undocumented `workflow_action: str` hint-field with a proper `str, Enum` type.
  Values: `warn`, `block` (default), `block_and_notify`, `require_human_review`,
  `escalate_to_senior`, `halt_and_alert`.  Old string values are still accepted via
  Pydantic coercion; empty string `""` coerces to `BLOCK`.
- **Enforced dispatch in `GovernanceEngine.validate()`**: the engine now routes
  violations by `workflow_action` instead of purely by severity:
  - `WARN` — non-blocking; violation goes to `result.warnings`, not `result.violations`.
  - `BLOCK / BLOCK_AND_NOTIFY / REQUIRE_HUMAN_REVIEW / ESCALATE` — blocks when `strict=True`,
    recorded when `strict=False` (always in `result.violations`).
  - `HALT` — always raises `ConstitutionalViolationError`, ignores `strict=False`.
- **`ValidationResult.warnings`** field (was a severity-derived property): now a first-class
  `list[Violation]` field populated by the engine with WARN-action violations.
- **`ValidationResult.action_taken`**: new `ViolationAction | None` field recording which
  enforcement action was applied (`HALT`, `BLOCK`, `WARN`, or `None` for allow).
- **`ConstitutionalViolationError.enforcement_action`**: new `ViolationAction` attribute
  (default `BLOCK`; set to `HALT` for circuit-breaker raises).
- **`ViolationAction` exported** from `acgs_lite` and `acgs` top-level packages.

### Changed
- `Rule.workflow_action` default changed from `""` to `ViolationAction.BLOCK`.
  MEDIUM/LOW advisory rules should now set `workflow_action=ViolationAction.WARN` explicitly.
- CRITICAL rules with `workflow_action=WARN` skip the hot-path early-exit; they are
  collected and dispatched non-blockingly like any other WARN violation.
- `serialization.py` always emits `workflow_action` in YAML/bundle output (was omitted
  when empty).
- `conflict_resolution.py` / `constitution.py`: conflict detection no longer guards on
  `workflow_action != ""` (now meaningless since the field always has a value).
- `dependency_analysis._KNOWN_WORKFLOW_ACTIONS`: added `halt_and_alert`.

### Fixed
- `ruff` config changed from `exclude` to `extend-exclude` so default dotfile
  exclusions (`.git`, `.venv`, `.codex-home`, etc.) are preserved.
- CI `ruff format --check` failure on `examples/mcp_agent_client.py` (trailing
  whitespace + lines > 100 chars); file auto-formatted.
- Test assertion in `test_coverage_engine_extra.py` for PAT-MED
  (`MEDIUM` severity / `WARN` action): corrected `result.violations` →
  `result.warnings`.

### Tests
- 32 new tests in `tests/test_workflow_action.py` covering `ViolationAction` enum
  coercion, WARN dispatch, HALT circuit-breaker, `action_taken` field, and
  backward-compatible string values.
- **Total: 4,687 passing, 156 skipped** (suite-wide)

## [2.6.0] - 2026-04-05

### Added
- **Leanstral Formal Verification**: `LeanstralVerifier` generates Lean 4 proof certificates
  via Mistral, producing `ProofCertificate` with `.to_audit_dict()` for audit trail attachment.
  Requires `mistralai` extra. 32 tests.
- **Engine correctness**: `_validate_rust_no_context` and `_validate_rust_metadata_context`
  now raise `ConstitutionalViolationError` for `_RUST_DENY` blocking violations (HIGH severity
  in strict mode), closing a gap where Rust dispatch could silently pass HIGH violations.
- **74 new constitutional_swarm tests**: Deep coverage for DAG immutability, MACI enforcement,
  ArtifactStore integrity, CapabilityRegistry routing, concurrency safety, and compiler edge cases.
- **Documentation refresh**: New guides — 2026 compliance landscape, MCP integration, OWASP LLM
  Top 10 mapping, supervisor model patterns, testing governance, use-case catalogue.
- **Stability classifier**: Promoted from Beta → Production/Stable.

### Changed
- `pyproject.toml` description: clearer one-line summary of capabilities.
- Keywords expanded: added `llm-safety`, `agentic-firewall`, `formal-verification`,
  `z3`, `lean4`, `hipaa`, `gdpr`, `nist-ai-rmf`, `ai-act`, `responsible-ai`.
- README: full rewrite — comprehensive feature tour, integration examples,
  compliance table, performance benchmarks, CLI reference, formal verification examples.

### Fixed
- `deploy-clinicalguard.yml`: `_parse_skill` now correctly routes explicit-but-unknown
  skill prefixes to the helpful-error path instead of falling through to `validate_clinical_action`.
- CI: `deploy` steps gated on `env.FLY_API_TOKEN` presence; no more parse errors from
  invalid `secrets` context in job-level `if` conditions.
- `examples/mcp_agent_client.py`: pass `StdioServerParameters` object to `stdio_client`
  instead of a plain dict (mcp SDK no longer accepts dict for server params).

### Deferred to post-v2.6.0
- mypy strict errors in `integrations/` adapters (pre-existing, `ignore_errors = true`)
- bandit security warnings in example scripts (pre-existing)
- LaTeX paper PDF build in release workflow (requires full TeX Live; non-blocking)

## 2026.1.0 - 2026-04-05

### Added
- **2026 Governance Frameworks**: Native support for EU AI Act, Colorado SB 205, and Texas TRAIGA.
- **Agentic Firewall**: New high-performance deterministic engine for runtime action interception.
- **MCP Governance Hub**: Full Model Context Protocol server integration for centralized safety.
- **Verification Kernels**: Support for Z3 SMT formal verification and Lean 4 proof certificates.
- **Governance Circuit Breaker**: Automated halting of "rogue" agents based on violation thresholds.
- **Expanded Documentation**: New guides for 2026 regulatory compliance, OWASP Top 10 for agents, and advanced safety patterns.

### Changed
- **Package Name**: Standardized on `acgs-lite` for the core engine.
- **Architecture**: Refactored to a Zero-Trust architecture with mandatory MACI role separation.
- **Audit Backend**: Optimized `JSONLAuditBackend` with cryptographic chaining (SHA-256).
- **Integrations**: Updated Anthropic, OpenAI, and LangChain adapters for 2026 model release lines.

## 2.5.2 - 2026-04-05

### Added
- Open-source distribution scaffolding: MkDocs documentation site, CONTRIBUTING.md,
  SECURITY.md, CODE_OF_CONDUCT.md, GitHub Actions CI/CD, issue and PR templates
- Apache-2.0 license with Commons Clause

### Fixed
- Updated all package URLs to individual GitHub repositories
- Pinned Node 22 and uv 0.10.9 in eval-rules and GitLab CI

## 2.5.1 - 2026-04-04

### Added
- `to_decision_record()` for cross-layer governance evaluation
- Autonoma E2E scenario definitions and QA test tracking

### Fixed
- CI test failures in tenant context blocking, OIDC mocking, and audit chain validation

## 2.5.0 - 2026-04-03

### Added
- Self-evaluation architecture (Phases 0-3): decision schema, LLM judge, shadow cascade
- Constrained decoding engine (`acgs_lite.constrained_decoding`)
- Multi-framework compliance assessor covering 9 regulatory frameworks (125 items)
- EU AI Act one-shot assessment CLI command
- CrewAI integration adapter
- A2A (Agent-to-Agent) integration
- PDF report generation (`acgs-lite[pdf]`)
- OpenTelemetry export (`acgs otel`)
- Policy lifecycle management (`acgs lifecycle`)
- Governance denial explanation (`acgs refusal`)

### Changed
- Upgraded MACI enforcer with risk-level-based escalation paths
- Improved constitutional validation performance with memoization

## 2.4.0 - 2026-03-15

### Added
- GitLab CI/CD integration with merge request governance bot
- Google GenAI integration adapter
- LlamaIndex integration adapter
- AutoGen integration adapter
- Cloud Run deployment support
- Hackathon starter examples

### Changed
- Expanded compliance coverage to HIPAA + AI, GDPR Art. 22, ECOA/FCRA, NYC LL 144

## 2.3.0 - 2026-02-20

### Added
- MCP Server integration (`acgs-lite[mcp]`)
- LiteLLM integration adapter
- ASGI/FastAPI governance middleware
- Batch validation support
- Constitutional merge and diff helpers

### Changed
- Improved audit trail with SHA-256 chain verification

## 2.2.0 - 2026-01-15

### Added
- LangChain integration (`GovernanceRunnable`)
- Constitution templates (`general`, `gitlab`)
- `ConstitutionBuilder` fluent API
- CLI: `acgs init`, `acgs lint`, `acgs test`

## 2.1.0 - 2025-12-01

### Added
- OpenAI integration adapter
- Anthropic integration adapter
- YAML constitution loading
- Severity levels (CRITICAL, HIGH, MEDIUM, LOW)

## 2.0.0 - 2025-10-15

### Added
- Initial public release
- `GovernedAgent` wrapper with constitutional validation
- `GovernanceEngine` with deterministic rule matching
- MACI role separation enforcement
- Tamper-evident audit trail
- CLI tool (`acgs` / `acgs-lite`)
- Keyword-based and regex rule matching

[Unreleased]: https://github.com/acgs-ai/acgs-lite/compare/v2.12.0...HEAD
[2.12.0]: https://github.com/acgs-ai/acgs-lite/compare/v2.11.0...v2.12.0
[2.11.0]: https://github.com/acgs-ai/acgs-lite/compare/v2.10.1...v2.11.0
[2.10.1]: https://github.com/acgs-ai/acgs-lite/compare/v2.9.0...v2.10.1
[2.9.0]: https://github.com/acgs-ai/acgs-lite/compare/v2.8.1...v2.9.0
[2.8.1]: https://github.com/acgs-ai/acgs-lite/compare/v2.7.2...v2.8.1
[2.7.2]: https://github.com/acgs-ai/acgs-lite/compare/v2.7.0...v2.7.2
[2.7.0]: https://github.com/acgs-ai/acgs-lite/compare/v2.6.0...v2.7.0
[2.6.0]: https://github.com/acgs-ai/acgs-lite/releases/tag/v2.6.0
