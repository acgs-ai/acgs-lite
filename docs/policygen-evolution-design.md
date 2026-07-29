# Policygen Evolution Design (Phase 3)

Mode: **DESIGN** — no code applied. Everything below is a design sketch for future
work, not an implementation plan with committed line numbers or PRs. Where this
doc names a module that does not exist yet, treat the name as illustrative.

Scope: extends the manifest capability adapter shipped in
`src/acgs_lite/policygen/manifest.py` and the `acgs policygen scan` verb
(`src/acgs_lite/commands/policygen.py`). See
[Agent-Native Adaptation Plan](agent-native-adaptation-plan.md) for the parity
work this builds on, and the `tools/runbooks/policygen.md` runbook
for the operator-facing `scan` / `generate` / lifecycle-submit flow this design
extends without changing.

**Governing rule for every section below:** every automation this document
proposes stops at *proposal generation*. None of it auto-activates a
constitution, mutates one in place, or expands a permission ceiling on its
own. A human (or the existing MACI-gated lifecycle) is the only path from
DRAFT to ACTIVE, exactly as today.

---

## 1. Manifest drift detection

**Idea.** Re-run `scan_manifests()` on a schedule, diff the new
`ManifestScanResult` against the last stored snapshot, and — only on a
non-empty diff — produce a DRAFT constitution-lifecycle proposal that carries
a `GovernancePolicySimulator.compare()` report.

**Design sketch.**

- A snapshot store (illustrative name: `ManifestSnapshotStore`) persists the
  `matched` / `unknown` / `manifests` tuples from `ManifestScanResult.to_dict()`
  (`src/acgs_lite/policygen/manifest.py:152-158`), keyed by scan target and
  timestamp. `ManifestScanResult` is already `frozen`/`slots` (`manifest.py:137`),
  so the store only ever appends immutable snapshots — it never mutates one.
- A scheduled job (cron, CI step, or operator-triggered) calls `scan_manifests()`
  again and diffs `matched`/`unknown` sets against the prior snapshot: new
  matched risk areas, dropped risk areas, and newly-unknown packages are all
  diff-worthy signals.
- On a non-empty diff, the job builds a candidate `PreContext` from the new
  scan (unchanged `scan_manifests` output — no new fields required) and runs
  it through the existing `AdaptivePolicyGenerator` to produce a candidate
  constitution, then calls `ConstitutionLifecycle.create_draft()`
  (`src/acgs_lite/constitution/lifecycle_router.py:191-202`) to attach it as a
  DRAFT bundle.
- The DRAFT is enriched with a `GovernancePolicySimulator.compare()` report
  (`src/acgs_lite/constitution/policy_simulator.py:229-266`), baseline =
  the tenant's currently active constitution, candidates = `{"manifest-drift":
  <candidate>}`, actions = a representative corpus (e.g. recent decision-log
  actions, see §3). The report's `blast_radius`, `regressions`, and
  `recommendation` fields ride along as DRAFT metadata for the human reviewer.

**Relationship to the existing decision-log drift detector.** This is a
distinct, complementary signal, not a duplicate of `GovernanceDriftDetector`
(`src/acgs_lite/constitution/drift.py:60-243`). That detector watches a
*decision stream* for behavioral patterns (`probing`, `gaming`,
`escalation_suppression`, `boundary_walking` — `drift.py:29-34`); it has no
notion of dependency manifests. Manifest drift instead watches a project's
*declared dependencies* for capability-evidence changes over time. The two
could feed the same review queue, but neither module needs to import the
other; they are two independent evidence sources into DRAFT proposals.

**Stops at proposal generation.** The job never calls `submit_for_review`,
`approve_review`, `approve`, `stage`, or `activate` — those remain a human
action through the lifecycle API, exactly as `tools/runbooks/policygen.md`
step 3 already documents for hand-authored briefs.

---

## 2. Evidence store / SBOM integration

**Idea.** Accept CycloneDX and SPDX SBOM documents as additional
`scan_manifests` input formats, alongside the existing `pyproject.toml` /
`requirements.txt` / `package.json` parsers, and record each scan as a durable
evidence receipt.

**Design sketch — new input formats (design only; SBOM parsing itself is
explicitly out of scope for implementation here).**

- New parser functions would follow the existing shape of `_parse_pyproject`
  (`manifest.py:219-276`), `_parse_requirements` (`manifest.py:279-296`), and
  `_parse_package_json` (`manifest.py:299-321`): each returns
  `(names, unparsed)` or `(names, unparsed, own_name)`, feeding the same
  `raw_names` / `unknown_raw` accumulation loop in `scan_manifests`
  (`manifest.py:352-396`). A CycloneDX parser would read `components[].name`
  (and `purl` for ecosystem-qualified names); an SPDX parser would read
  `packages[].name`. Both stay text/JSON-only — no SBOM tool invocation, no
  network fetch of referenced package registries.
- The same size guard (`_MAX_MANIFEST_BYTES`, `manifest.py:115`) and
  size-then-decode read path (`_read_manifest_text`, `manifest.py:166-183`)
  apply unchanged; SBOM files are just another untrusted-text input.
- Unknown/unparsed component names flow into the existing `unknown` set
  exactly like an unparsed `requirements.txt` line — the "never silently
  dropped" invariant (`manifest.py:28-29`) extends to SBOM inputs by
  construction, not by a new code path.

**Evidence receipts.** Each scan (manifest-only or SBOM-augmented) would
produce a receipt: scan target, timestamp, a content hash of every manifest
file read (so a later dispute — "what did the scanner actually see?" — is
answerable), the `matched`/`unknown` tuples, and, if the scan fed a DRAFT
proposal, the resulting bundle ID. Receipts are pure evidence, mirroring how
`ManifestScanResult` itself is evidence-only (`manifest.py:13-20`) — a receipt
records that a scan happened and what it saw, never that anything was
authorized.

**Stops at proposal generation.** SBOM ingestion only ever widens the input
side of `scan_manifests`; it produces the same `ManifestScanResult` /
`PreContext` shape that already flows into `--generate` and DRAFT review
today. No new activation path.

---

## 3. Runtime telemetry correlation

**Idea.** Cross-reference manifest-derived evidence (declared capabilities)
against `observability/` decision logs (observed capabilities) to flag two
kinds of mismatch.

**Design sketch.**

- The observability side already emits structured, replayable records:
  `ToolObservation` (`src/acgs_lite/observability/session_observer.py:72-112`)
  captures `tool_type`, `file_paths`, and `metadata` per tool call, appended
  as JSONL (`ObservationLogger._append`, `session_observer.py:212-215`).
  `analyze_observations.py` already buckets tool calls into categories
  (`EXPLORATION_TOOLS`, `PRODUCTION_TOOLS`, etc., `analyze_observations.py:23-48`).
- A new correlation pass (illustrative name: `TelemetryCorrelator`) would map
  observed tool/command patterns onto the same risk-area vocabulary
  `CAPABILITY_MAP` already uses (`manifest.py:86-109`) — e.g. a `bash`
  observation whose `metadata["command"]` touches `boto3`/`gcloud` maps to
  `production-deploy`; an observation writing to a file matching `*.pem`/
  `secrets*` maps to `secrets`. This reuses the manifest adapter's existing
  risk-area keys rather than inventing a second vocabulary.
- Two flag types per correlation run:
  - **Observed-but-not-declared**: a risk area appears in runtime telemetry
    but not in the latest `ManifestScanResult.matched` — e.g. an agent
    invoking `boto3` calls when no manifest declares `boto3`. This is the
    more actionable flag (possible undeclared dependency, vendored code, or
    dynamic import) and is the natural DRAFT-proposal trigger: "manifest
    evidence is stale, consider re-scanning or reviewing this activity."
  - **Declared-but-never-observed**: a risk area is `matched` in the manifest
    but never appears in any decision-log window — e.g. `stripe` is a
    dependency but no financial-shaped action has ever been decided on. This
    is a lower-urgency signal (dead dependency, unused feature) surfaced as
    an advisory note, not a proposal trigger by itself.
- This correlator can share an action corpus with §1's simulator comparison —
  recent decision-log actions are a natural, already-recorded input to
  `GovernancePolicySimulator.compare(actions=...)`.

**Relationship to `GovernanceDriftDetector`.** Same relationship as §1: this
is a third, independent evidence source (telemetry-vs-manifest mismatch)
alongside decision-stream behavioral drift (`drift.py`) and manifest-over-time
drift (§1). None of the three subsumes another; a future review queue could
consume all three, but each stays a standalone, composable signal.

**Stops at proposal generation.** Correlation output is advisory text plus,
for the observed-but-not-declared case, an optional DRAFT proposal suggesting
a re-scan or a manual `add_risk_area` addition — never an automatic
`add_risk_area` call, and never a change to an already-active constitution.

---

## 4. Capability graph (research-only)

**Idea.** Fuse the static evidence source (`CAPABILITY_MAP` matches) with the
dynamic evidence source (§3's tool-call telemetry) into a graph: nodes are
risk areas / packages / tool categories, edges are co-occurrence or
correlation strength between them.

**This section is explicitly research-only.** No schema, API, or storage
format is committed here. It exists to name the open problems honestly before
any implementation is attempted.

**Open problems.**

- **Normalization across ecosystems.** `CAPABILITY_MAP` keys are
  Python/npm package names (`manifest.py:86-109`); telemetry-derived nodes
  (§3) are command/tool-shaped. There is no agreed canonical node identity
  that both sides can converge on without either losing precision (fully
  qualified `purl`s) or losing recall (loose keyword matching).
- **Temporal weighting.** A capability observed once six months ago and a
  capability observed in every session this week are not the same signal
  strength, but the graph as sketched has no principled decay function yet.
- **False positive / false negative rates are unmeasured.** Neither the
  static matcher nor a plausible telemetry matcher has been validated against
  a labeled corpus; presenting graph edges as trustworthy before that
  validation exists would misrepresent confidence.
- **Graph poisoning is a first-class risk, not an afterthought.** Because the
  graph fuses two evidence sources, an attacker who can influence either one
  (a malicious manifest entry, a crafted sequence of tool calls) can shape
  graph structure. See §6 for why this composes with, but does not worsen,
  the existing map-poisoning threat.
- **No activation semantics are proposed.** Even once open problems above are
  addressed, a capability graph is analysis output for a human reviewer —
  the same DRAFT-only ceiling as every other section in this document.

**Stops at proposal generation** — trivially, since this section has no
proposal-generation path defined at all yet; it is upstream research input to
sections 1 and 3, not an independent trigger.

---

## 5. Formal verification (experimental)

**Idea.** Extend `src/acgs_lite/z3_verify.py` to check *properties of a
generated constitution itself* — before it reaches
`GovernancePolicySimulator.compare()` — rather than only verifying individual
runtime actions as `Z3ConstraintVerifier.verify()` does today
(`z3_verify.py:204-278`).

**Why pre-simulation.** `GovernancePolicySimulator.compare()` answers "what
changes relative to the baseline, for this action corpus?" — a comparison
that is only as good as the action corpus it's fed. A property check answers
a corpus-independent question: "does this generated constitution satisfy an
invariant for *every* rule, not just the rules exercised by my test
actions?" The two are complementary layers, matching the existing Layer
1/2/3 framing in `z3_verify.py:8-11` (keyword rules → semantic scoring →
formal verification) — this adds a fourth check that runs on the generated
*artifact*, ahead of Layer 1-3 runtime checks on individual *actions*.

**Design sketch.** An illustrative `verify_constitution_properties()`
function would:

1. Enumerate rules from a `GeneratedPolicy`/`Constitution` object (the same
   object `AdaptivePolicyGenerator.generate()` already returns).
2. For each declared property, encode it as Z3 booleans keyed by rule ID,
   using the same locked-down evaluation pattern the module already uses for
   policy strings (`_POLICY_EVAL_GLOBALS`, `z3_verify.py:54-60`, applied at
   `z3_verify.py:526` and `:665`) — no new `eval()` surface, no new builtins
   exposure.
3. Assert the negation of the property and check satisfiability, exactly the
   pattern `Z3ConstraintVerifier.verify()` already uses
   (`z3_verify.py:230-267`): SAT on the negation means a counterexample rule
   exists; UNSAT means the property holds for every rule.
4. Gracefully skip (return `solver_result="skipped"`, same shape as today's
   `Z3_AVAILABLE` fallback, `z3_verify.py:220-228`) when `z3-solver` isn't
   installed — this stays advisory, not a hard gate on generation.

**One worked example property.** `docs/api/policygen.md`'s adaptation table
already documents an intended invariant: *"`environment = production` →
blocking CRITICAL rules become `block_and_notify`"* (`docs/api/policygen.md:24`).
Today that invariant is produced by generator logic but never independently
checked. A worked Z3 encoding:

```text
For each rule r in the generated constitution:
  critical(r)      := (r.severity == CRITICAL)
  production_env(r) := (r.metadata.get("environment") == "production"
                         or precontext.is_production())
  blocking(r)       := (r.enforcement_action == "block_and_notify")

Property (must hold for all r):
  Implies(And(critical(r), production_env(r)), blocking(r))

Verification: assert Not(Property) for each r; check().
  UNSAT for all r  -> property holds, no counterexample.
  SAT for some r   -> counterexample gives the offending rule id,
                       severity, and enforcement_action.
```

This is a genuine gap-finder: it would catch a future generator regression
where a CRITICAL production rule is emitted with a non-blocking action,
independent of whatever action corpus a simulator run happens to exercise.

**Experimental, not a gate.** This check runs *pre-simulation*, as an
additional advisory report attached to the DRAFT bundle (same attachment
point as §1's `GovernancePolicySimulator.compare()` report) — it does not
block `AdaptivePolicyGenerator.generate()` from returning, and does not block
lifecycle submission. A SAT counterexample is a strong signal for a human
reviewer, not an automatic rejection.

**Stops at proposal generation.** The check only ever annotates a DRAFT
bundle with additional evidence; it has no write path to an active
constitution.

---

## 6. Threat model update

### Assets

- Dependency-manifest scan evidence (`ManifestScanResult`, evidence receipts
  from §2).
- The curated `CAPABILITY_MAP` (`manifest.py:86-113`) — a reviewed trust
  anchor mapping package names to risk areas.
- DRAFT constitution bundles produced by any of §1/§2/§3/§5's automation.
- Manifest snapshots (§1) and the capability graph (§4, research-only).
- Runtime telemetry (`ToolObservation` records, §3).

### Trust boundaries

- **Scanner input is untrusted file content.** Manifest text, and (design,
  §2) SBOM documents, come from the scanned project — potentially hostile.
  Hardening already in place and preserved by every extension in this
  document: a hard size cap before any parse
  (`_MAX_MANIFEST_BYTES`/`_read_manifest_text`, `manifest.py:115`, `166-183`),
  strict UTF-8 decode-or-reject, `ValueError` on malformed TOML/JSON rather
  than an unrelated crash (`manifest.py:233-236`, `304-309`), and — the
  hardest boundary — **no code execution of scanned content**: `manifest.py`
  "never imports, introspects, or executes target-project code or any
  discovered package" (`manifest.py:22-27`). Any SBOM parser (§2) or
  telemetry mapper (§3) added later must preserve this: text/JSON parsing
  only, never a `purl` resolution that fetches or imports the named package.
- **The curated map is a reviewed trust anchor.** `CAPABILITY_MAP` is a
  single, immutable (`MappingProxyType`, `manifest.py:113`), version-
  controlled literal (`manifest.py:30-33`) that changes only through normal
  code review. Nothing this document proposes lets scanner input, telemetry,
  or an LLM write to this map at runtime.

### Abuse cases

- **Map poisoning via PR.** An attacker submits a PR that edits
  `CAPABILITY_MAP` to misclassify a risky package as a lower-risk area, or to
  omit a package from the map entirely (so it silently lands in `unknown`
  instead of a matched risk area). Mitigation is unchanged by this design:
  normal PR review plus the "zero-gaps" test discipline the module docstring
  requires (`manifest.py:30-33` — every map value must be a real knowledge-
  base key, enforced by test). This document adds no automated write path to
  the map, so poisoning still requires a reviewed, human-merged commit.
- **Dependency-name squatting to force a permissive area.** An attacker
  publishes a package whose name collides with (or is confusable with) a
  package the map already classifies as low-risk, hoping a target project
  depends on it and gets under-classified. **The map only ever *adds* risk
  areas — it never grants, removes, or de-escalates permissions.**
  `scan_manifests` feeds matched risk areas into `PreContextBuilder.add_risk_area`
  (`manifest.py:406-407`), and `_classify_risk` only ever *escalates* toward
  `HIGH`/`UNACCEPTABLE` when more risk areas are present (`context.py:318-328`)
  — it has no path that lowers risk level as risk areas accumulate. So
  squatting a name that happens to collide with a mapped package can, at
  worst, add a spurious risk area (more scrutiny, tighter permission
  ceiling per `docs/api/policygen.md:26`) — it cannot loosen anything. An
  attacker gains nothing from squatting *toward* permissiveness; the
  mechanism structurally tightens, never loosens.

### Forbidden list (verbatim)

The following are hard constraints on every design in this document, not
suggestions:

- no auto-activation
- no automatic constitution mutation
- no dependency-based permission expansion
- no hidden trust escalation
- no opaque LLM-generated rules without provenance + DRAFT gating

---

## 7. Architecture impact analysis

### Layers unchanged

| Layer | Current implementation | Gains surface (this design) |
| --- | --- | --- |
| Discovery | `acgs policygen scan`, runbook | §1 re-scan job, §2 SBOM inputs |
| Reasoning | `PolicyResearcher`, generator | §3 telemetry correlator, §4 graph |
| Authorization | `ConstitutionLifecycle` saga | none — stays DRAFT-only |
| Execution | Engine, `Z3ConstraintVerifier` | §5 pre-sim check, advisory only |

No design in this document adds a module to the Authorization or Execution
layers. §1's drift job and §2's SBOM ingest widen Discovery (more ways to
surface evidence). §3 and §4 widen Reasoning (more evidence fused into
research input). §5 adds an *advisory* Execution-adjacent check that runs
before simulation, not inside the enforcement hot path — it never touches
`GovernanceEngine`'s runtime `validate()` call.

### Invariant-by-invariant: not weakened

| Invariant | Evidence (file:line) |
| --- | --- |
| Manifest scanning never activates anything | `manifest.py:27`, `commands/policygen.py:143-182` |
| Unknown packages never silently dropped | `manifest.py:28-29`, `manifest.py:381-391` |
| `CAPABILITY_MAP` is a single reviewable literal | `manifest.py:30-33`, `manifest.py:111-113` |
| Adapter never hand-sets `risk_level` | `manifest.py:33-34`, `manifest.py:408-410` |
| DRAFT requires explicit lifecycle submission | `lifecycle_router.py:191-219` |
| No self-approval (actor from header, not body) | `lifecycle_router.py:6-9`, `:164-174` |
| Static-only scanning, no code execution | `manifest.py:22-27`, `manifest.py:166-183` |
| Z3 verification degrades gracefully, never a hard gate | `z3_verify.py:34-39`, `:220-228` |
| Policy `eval` sandboxed from builtins | `z3_verify.py:54-60`, used at `:526`, `:665` |

Notes on the less self-explanatory rows:

- **Manifest scanning never activates anything** — `manifest.py:27`'s
  docstring states the contract; `commands/policygen.py`'s `_scan` handler
  (`:143-182`) never calls any `ConstitutionLifecycle` method.
- **DRAFT requires explicit lifecycle submission** — `create_draft` and
  `submit_for_review` (`lifecycle_router.py:191-219`) are the only path from
  a generated YAML to a bundle, and submission is a separate, explicit call;
  see also `tools/runbooks/policygen.md:94-99` (step 3, "Review and approve").
- **No self-approval** — the module docstring (`lifecycle_router.py:6-9`)
  states actor identity comes from `X-Actor-ID`, not the request body;
  `_get_actor` (`:164-174`) enforces that by reading the header only.
- **Static-only scanning** — `manifest.py:22-27`'s docstring states the
  no-import/no-exec contract; `_read_manifest_text` (`:166-183`) is a plain
  size-checked `Path.read_text`, never an import or subprocess call.

Every row above is unchanged by this document — each section was designed to
compose with the existing invariant rather than touch it. Where a new module
is proposed (snapshot store, evidence receipts, telemetry correlator,
capability graph, constitution-property checker), it is additive: it reads
existing evidence-producing functions and writes only to new, DRAFT-scoped
storage, never to the map, the lifecycle's ACTIVE state, or the scanner's
read-only I/O path.

---

## See also

- [Agent-Native Adaptation Plan](agent-native-adaptation-plan.md) — the
  parity-focused predecessor plan this document extends into Phase 3.
- `tools/runbooks/policygen.md` — the operator-facing
  `scan` / `generate` / lifecycle-submit flow every design above still ends
  at.
- [Adaptive Policy Generation reference](api/policygen.md) — API surface for
  `PreContextBuilder`, `PolicyResearcher`, `AdaptivePolicyGenerator`.
- [Architecture: Governed Execution Lifecycle](architecture.md) — MACI roles
  and the Constitution Lifecycle bundle saga referenced throughout §1, §6, §7.
