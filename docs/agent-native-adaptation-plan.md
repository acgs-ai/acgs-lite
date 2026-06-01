# Agent-Native Adaptation Plan — policygen (feat/adaptive-policy-gen)

Mode: **PLAN** (no code applied). Scope: the 7 in-scope uncommitted files only. All proposals below survived 3-lens adversarial verification; where a verifier revised a sketch, the revised form is used.

## TL;DR

- **The whole policygen pipeline is a Python-only island.** `PreContextBuilder → PolicyResearcher → AdaptivePolicyGenerator.write_yaml` is reachable only by `import` — there is no `commands/policygen.py`, no `python3 -m acgs_lite.policygen`, and zero mention in `tools/registry.yaml` or `tools/runbooks/`. An agent following the onboarding "discover via registry" flow never learns this subsystem exists. Closing this (entrypoint + registry entry + runbook) is the single highest-leverage parity win.
- **Make the curated vocabulary discoverable.** The KB (`_RISK_AREA_KB`/`_FRAMEWORK_KB` in research.py:118/214) and aliases (context.py:58-136) are all module-private and unexported. Add read-only `known_risk_areas()`/`known_frameworks()` introspection so an agent that hits a `gaps` entry can map its typo to a real key and self-correct — purely deterministic, read-only over existing constants.
- **Enrich the `gaps` self-diagnosis signal.** research.py already drops unknowns into `gaps` (342/350); appending the sorted known-key list turns an opaque error into an actionable, fully-deterministic correction hint — no behavior change to the requirement set.
- **Round-trip the brief.** `PreContext.to_dict` exists (context.py:174) but there is no inverse; add `PreContext.from_dict` so a brief can be written, committed, and re-read by a second agent — mirroring how the rest of the subsystem round-trips `Constitution` through files. This is the data ingest the CLI needs.
- **Tighten artifact-fidelity tests.** Assert per-rule **provenance** survives the YAML file round-trip (test_policygen.py write path) so the file surface an agent uses matches the in-memory API surface.

## Per-file findings

### `src/acgs_lite/policygen/research.py`
Scorecard: parity **weak** (KB + `research()` Python-only, unexported) · granularity **weak** (KB is code) · composability **net-positive** (structured `sources` provenance) · emergentCapability **bounded-by-design** (unknowns → `gaps`, never synthesized) · improvementOverTime **weak** (no external data path).

Kept adaptations:
- **research-1 — Expose KB discovery as public introspection** (parity, S/low). Add `known_risk_areas() -> tuple[str, ...]` (`tuple(_RISK_AREA_KB)`) and `known_frameworks() -> tuple[str, ...]` (`tuple(_FRAMEWORK_KB)`), both pure/read-only, exported in `__all__` (research.py:430). Insertion-order is deterministic. `describe_knowledge_base()` is **dropped** as the default — it duplicates `ResearchReport.to_dict()` and is a doc-dump, not capability discovery; reintroduce only if a concrete agent flow needs requirement bodies before running `research()`. No change to `research()`/`_dedupe`.
- **research-2 — Enrich unmatched `gaps` with the discoverable vocabulary** (rich/actionable-output → self-correction, S/low). In `research()`, keep the existing prefix and append known keys as a suffix, e.g. `f"risk-area:{area} (no knowledge-base entry; known: {', '.join(sorted(_RISK_AREA_KB))})"` and the framework mirror. Use `sorted()` for stable audit/diff output; swap to the research-1 helpers if they land, but do not block on them. Add a test pinning both the original `"risk-area:{area} (no knowledge-base entry"` prefix (backward compat) and the new known-key listing.
- **research-3 — Optional caller-supplied KB overlay** (improvementOverTime, M/medium). Extend `PolicyResearcher.__init__` (331) with `extra_risk_areas: Mapping[...] | None` and `extra_frameworks: Mapping[...] | None`, stored as frozen `dict(...)` snapshots so post-construction mutation cannot affect determinism. **Built-in KB is authoritative**: look up `_RISK_AREA_KB`/`_FRAMEWORK_KB` first, consult overlay only for absent keys (additive, never shadowing). Tag overlay requirements with a distinct `source=f"overlay:risk-area:{area}"` prefix so audit can separate injected from curated rules. Validate each spec (non-empty `text`, raise clear `ValueError` not bare `KeyError`). Reuse `_spec_to_requirement` (308). Document additive-only/caller-supplied/never-networked semantics in the class docstring. Tests: overlay-adds, overlay-collides-builtin-wins, overlay-miss-falls-through, provenance prefix, malformed-raises-ValueError.

### `src/acgs_lite/policygen/generator.py`
Scorecard: parity **none** (no CLI/tool; pure Python API) · granularity **code-not-prose** (correct trade for determinism-first) · composability **closed** (new adaptation = code edit) · emergentCapability **bounded-by-design** (round-trip hash guard 147-152 rejects unmodeled artifacts) · improvementOverTime **none** (constants only).

Kept adaptation:
- **parity-1 — Expose generation as an `acgs` CLI/tool surface** (parity, M/low). Add a command module under `src/acgs_lite/commands/` mirroring `acgs arckit` routing: build a `PreContext` via `PreContextBuilder.infer()` from flags (`--domain/--description/--env/--framework/--risk-area/--risk-level`), call `AdaptivePolicyGenerator().write_yaml(precontext, out)`, emit `GeneratedPolicy.summary` (212-225) + rationale (85) as structured stdout. No logic moves out of generator.py — it stays the callee. (See cross-cutting CC-2; this is the per-file face of the same gap.)

Dropped: externalize adaptation tables into a data file; promote rationale/summary into a structured decision record — both flagged scope-guard/YAGNI for a determinism-first library.

### `src/acgs_lite/policygen/context.py`
Scorecard: parity **gap** (`to_dict` exists, no inverse constructor) · granularity **frozen literals** (alias/domain tables in code) · composability **good** for builders, **closed** for vocabulary packs · emergentCapability **partial** (`infer()` generalizes, but `UNACCEPTABLE` tier declared yet never produced) · improvementOverTime **none**.

Kept adaptation:
- **context-3 — Make `_classify_risk` capable of producing the declared `UNACCEPTABLE` tier** (emergentCapability, S/low). `DomainRiskLevel.UNACCEPTABLE` (42) and its rank (52) exist but `_classify_risk` (260-270) can never return it. Before the `_HIGH_RISK_DOMAINS` check (261), add a check for **prohibited Article 5 practices** (frame as practices, not domains): a small documented `frozenset` e.g. `{"social scoring", "subliminal manipulation", "vulnerability exploitation", "social credit"}`. Match via the existing word-boundary `_contains_alias` helper (not raw `in`) so a false positive cannot hard-stop and escalate every rule's permission ceiling. Keep aligned with / cross-referenced to the authoritative `src/acgs_lite/eu_ai_act/risk_classification.py` Article 5 set (mirror, not import — avoid a second drifting definition). Preserve the explicit `with_risk_level` override guard (256-257, untouched). Tests: prohibited-practice → UNACCEPTABLE, a near-miss negative that must stay HIGH/LIMITED, and existing HIGH/LIMITED/MINIMAL cases at test_policygen.py:96-113 unchanged.

Dropped: `PreContext.from_mapping` and supplemental-vocabulary loading are handled at the cross-cutting level (CC-3, CC-4) rather than as standalone per-file YAGNI items.

### `scripts/sync_agents.py`
Scorecard: parity **near-full** (write/check map to operator actions; only missing a "why is a manifest stale" diff verb) · granularity **strong** (behavior is data in `agent-index.json`) · composability **good** (small importable pure fns) · emergentCapability **moderate** · improvementOverTime **weak-by-design, acceptable** (deterministic codegen, not a learning loop).

Kept adaptation:
- **granularity-1 — Make the agent metadata contract prose-discoverable** (granularity, S/low). Extend the module docstring (L2-17) with a one-sentence "Required metadata contract" pointer. Verifiers split on mechanism — choose one:
  - *Prose-only (minimal):* list the string keys (`purpose`, `scope`, `execution_command`) and list keys (`required_tools`, `inputs`, `outputs`, `safety_constraints`, `validation_checks`, `expected_artifacts`, `failure_modes`), noting they are enforced by `validate_agent_index()` and surfaced via `python3 scripts/sync_agents.py --check`. No flag, no runbook cross-ref.
  - *Drift-proof (preferred if any duplication risk):* add a read-only `--print-contract` flag to `main()` that dumps the live `_REQUIRED_METADATA_STRING_KEYS`/`_REQUIRED_METADATA_LIST_KEYS` tuples (single source of truth), and have the docstring point at the flag rather than enumerate keys inline.

  Recommendation: take the **drift-proof** variant — hand-copying key names into prose creates exactly the second-source-of-truth drift this file already avoids elsewhere. No change to validate/build/check/write logic.

Dropped: `--json` drift output; per-manifest diff verb — scope-guard/YAGNI.

### `scripts/validate_tools.py`
Scorecard: parity **strong** (drift guard keeps `registry.yaml` honest against live make targets/scripts/modules) · granularity **appropriately primitive** (`validate()` returns `list[str]`) · composability **good** (folds into `agent_ready.py:128`) · emergentCapability **partial** (richer evidence strings added, but `main()` emits prose only) · improvementOverTime **weak** (re-implements a subset of `tools/schemas/tool.schema.json` — two sources of truth).

Kept adaptations: **none** (all proposals dropped).

Dropped: validate against `tool.schema.json` instead of re-implementing key lists; `--json` output mode for `main()`; verify `owner_module` resolves — all scope-guard/YAGNI for this PR. (Note: the schema-vs-validator dual-source-of-truth is a real latent drift risk, but out of scope here.)

### `tests/test_policygen.py`
Scorecard: parity **strong** (drives the public façade through the real `Constitution`/`GovernanceEngine` path, not mocks) · granularity **mixed** (outcome-level, but content governed by code KB) · composability **good** (injected `StubProvider`/`StubResearcher`) · emergentCapability **weak-by-design, appropriate** · improvementOverTime **limited** (one private-symbol coupling to `_dedupe` at L175).

Kept adaptations:
- **composability-1 — Assert custom risk-areas compose without KB edits** (composability, S/low). In `test_unknown_area_recorded_as_gap`, build `PreContext(domain="X", risk_areas=("pii", "nonsense-area"))`. Assert (1) exactly one requirement with `source == "risk-area:pii"` (known composes alongside unknown), and (2) `any(g.startswith("risk-area:nonsense-area") for g in report.gaps)` — assert the **stable prefix only**, NOT the `(no knowledge-base entry)` parenthetical, so incidental gap prose is not frozen into a fake contract. No production change.
- **parity-1 — Artifact-fidelity: assert provenance survives the YAML file round-trip** (parity, S/low). In `test_write_yaml_to_disk`, after `loaded = Constitution.from_yaml(...)`, build the in-memory policy once (`policy = AdaptivePolicyGenerator().generate(...)`) and assert per-rule **provenance** parity keyed by id: `{r.id: list(r.provenance) for r in loaded.rules} == {r.id: list(r.provenance) for r in policy.constitution.rules}`. Do **not** re-assert severity — it is already pinned by the production round-trip hash check at generator.py:148-152, so a severity assertion is vacuous; provenance is omitted from the hash and is the genuinely unguarded field. Keep the existing rule-count assertion. No production change.

Dropped: data-driven KB fixture round-trip test; decouple from private `_dedupe` symbol — scope-guard/YAGNI/safety.

### `tools/runbooks/setup.md`
Scorecard: parity **strong** (every step is an agent-invokable command/script) · granularity **good** (prose + Make/script refs) · composability **good** · emergentCapability **adequate** (`agent_ready.py --json` readiness contract) · improvementOverTime **weakest** (failure-mode table is the accumulation surface but nothing invites appending to it).

Kept adaptations:
- **improvement-1 — Invite agents to append new setup failures to the failure-mode table** (improvementOverTime, S/low). Add one sentence after the failure-mode table (after L38): when an agent hits an unlisted setup failure, append a Symptom/Cause/Fix row in the same PR (deterministic prose, no code); route durable code-level invariants to CLAUDE.md's Compounding Knowledge table instead, and do not duplicate a row across both. Drop the `files-universal-interface.md` reference — that file does not exist.
- **parity-1 — Align the readiness command with agent-onboarding.md (`--run-tests`)** (parity, S/low). Change L29 to `python3 scripts/agent_ready.py --json --run-tests` so setup.md exercises the same `targeted-tests` gate (`run_targeted_tests`, collect_checks L303-304) as agent-onboarding.md:34. Prefer the flag-add over a prose footnote — it closes the parity gap rather than documenting it. Optional accurate caveat: omitting `--run-tests` does not *fail* readiness (the `_required_skips` path at agent_ready.py:320-325 exempts `targeted-tests`); it only yields a less-covered `passed`.

## Cross-cutting adaptations

These span multiple files; no single in-scope file owns them. They are deliberately sequenced: **CC-3 → CC-2 → CC-1** form one dependency chain (data ingest → entrypoint → catalog), because `validate_tools.py` will reject a registry/runbook entry that points at a non-existent callable.

- **CC-1 — Surface the pipeline in the agent tool catalog** (parity, M). Add one `tools/registry.yaml` entry (`name: policygen`, `command:` the thin wrapper from CC-2, `owner_module: src/acgs_lite/policygen`) plus `tools/runbooks/policygen.md` walking `PreContextBuilder.infer() → AdaptivePolicyGenerator.write_yaml() → *.constitution.yaml`. Must point at a real callable (CC-2) so `validate_tools.py` passes. Deterministic/offline by default; LLM provider stays caller-injected.
- **CC-2 — Add a CLI/module entrypoint wrapping the pipeline** (composability, M). Add `commands/policygen.py` (or `__main__.py`): load a `PreContext` from JSON/YAML (via CC-3), call `AdaptivePolicyGenerator().write_yaml(precontext, out)`, print the summary as JSON. Pure composition over the already-exported public API — no logic leaves the library. This is generator.py's per-file parity-1 realized at subsystem level (they are the same fix; do not double-count).
- **CC-3 — Add `PreContext.from_dict` (and optionally `from_yaml_str`)** (parity, S). Inverse of `to_dict` (context.py:174), mapping `risk_level` back through `DomainRiskLevel`. Deterministic, no new deps. Unblocks the write-brief → commit → CLI-reads-brief → emit-constitution agent-to-agent handoff that the rest of the subsystem already enjoys via `Constitution.from_yaml`.
- **CC-4 — Caller-supplied KB/vocabulary overlay across context.py + research.py** (improvementOverTime, L). The single largest agent-native gap, spanning the private literals in context.py:58-136 and research.py:118/214. Add an optional runtime overlay: `PolicyResearcher(extra_risk_areas=..., extra_frameworks=...)` (this **is** research-3 — same fix, do not double-count) and a parallel `PreContextBuilder` vocab overlay, loadable from a workspace data file. Keep hardcoded tables as the deterministic default/fallback (preserves auditability and the Python-fallback constraint); merge deterministically (built-in authoritative, overlay additive-only) so output is reproducible given the same overlay. Directly relevant to the Aug 2026 EU AI Act Art. 50 deadline in the growth-strategy memory — new article references could land as data, not a release. Largest effort; sequence last.
- **CC-5 — Discoverable vocabulary for self-correction** (emergentCapability, S). research.py emits actionable `gaps` but the correction dictionary is undiscoverable. This is realized by research-1 (`known_risk_areas()`/`known_frameworks()`, exported in `__all__`) + research-2 (gap enrichment) + surfacing via the CLI `--list-vocabulary --json`. **Same fixes as research-1/research-2** — listed here only to name the cross-file principle; do not double-count effort.

## Prioritized backlog

| Rank | Change | Principle | Files touched | Effort | Risk | Why now |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `PreContext.from_dict` inverse constructor (CC-3) | Parity | context.py | S | low | Unblocks the CLI ingest (rank 2) and agent-to-agent brief handoff; smallest piece of the parity chain |
| 2 | CLI/module entrypoint wrapping the pipeline (CC-2 = generator parity-1) | Composability | new `commands/policygen.py` | M | low | The lone Python-only governance surface; every sibling (`arckit`, `assess`, `eu_ai_act`…) is agent-operable. Needs rank 1 for ingest |
| 3 | Registry entry + `policygen.md` runbook (CC-1) | Parity | `tools/registry.yaml`, `tools/runbooks/policygen.md` | M | low | Agents discover capabilities via the catalog; today policygen is invisible there. Needs rank 2 to reference a live callable |
| 4 | `known_risk_areas()` / `known_frameworks()` introspection (research-1, CC-5) | Parity / EmergentCapability | research.py | S | low | Read-only, deterministic; the correction dictionary an agent needs when it hits a gap |
| 5 | Enrich `gaps` with known-key hint (research-2) | Self-correction | research.py | S | low | Turns an opaque error into an actionable, deterministic hint; pairs with rank 4 |
| 6 | Artifact-fidelity: provenance survives file round-trip (test parity-1) | Parity | tests/test_policygen.py | S | low | Closes the only unguarded governance field across the file surface; cheap regression lock |
| 7 | Custom risk-areas compose without KB edits (test composability-1) | Composability | tests/test_policygen.py | S | low | Pins the parseable-gap + known-area-still-composes contract; complements ranks 4-5 |
| 8 | setup.md `--run-tests` alignment (runbook parity-1) | Parity | tools/runbooks/setup.md | S | low | One-line fix removes a real readiness-surface divergence between the two runbooks |
| 9 | `_classify_risk` can emit `UNACCEPTABLE` (context-3) | EmergentCapability | context.py | S | low | Closes a declared-but-unreachable top tier; word-boundary match + Art. 5 alignment keeps it safe |
| 10 | Agent metadata contract discoverability (`--print-contract`) (sync granularity-1) | Granularity | scripts/sync_agents.py | S | low | Makes the de-facto schema queryable without a drift surface |
| 11 | setup.md failure-mode "append a row" convention (runbook improvement-1) | ImprovementOverTime | tools/runbooks/setup.md | S | low | Turns a static table into a compounding-knowledge surface for free |
| 12 | Optional caller-supplied KB overlay (CC-4 = research-3) | ImprovementOverTime | research.py (+ context.py vocab) | M–L | medium | Largest agent-native gap (feature-as-data vs feature-as-code); EU AI Act Art. 50 timing. Sequence last — medium risk, biggest surface |

## Explicitly out of scope / dropped

- **Externalize generator adaptation tables to a data file** — scope-guard/YAGNI; determinism-first ladder is a correct trade.
- **Structured machine-replayable decision record for rationale/summary** — YAGNI; the summary dict already serializes.
- **`describe_knowledge_base()` full text/severity projection** — duplicates `ResearchReport.to_dict()`; doc-dump, not capability discovery. Reconsider only on a concrete need.
- **`validate_tools.py` validate-against-`tool.schema.json`, `--json` mode, `owner_module` resolution** — real latent dual-source-of-truth drift, but out of scope for this PR.
- **`sync_agents.py` `--json` drift output and per-manifest diff verb** — YAGNI; `--check` error output already serves as the queryable contract.
- **test_policygen.py data-driven KB fixture round-trip; decouple from private `_dedupe`** — YAGNI/safety; the suite already drives the public façade through the real engine.
- **Standalone `PreContext.from_mapping` and `PreContextBuilder` vocab-pack loading as per-file items** — folded into cross-cutting CC-3/CC-4 to avoid double-counting.

## Constraint check

All adaptations are read-only introspection, additive prose/tests, deterministic string enrichment, or composition over the already-exported public API — none imports an optional SDK at module-import time, none bypasses MACI enforcement, none touches `matcher.py` hot-path behavior, and all preserve fail-closed determinism (overlays/CLI are caller-injected and offline-by-default, built-in KB stays authoritative, and the round-trip hash guard at generator.py:148-152 is unchanged).
