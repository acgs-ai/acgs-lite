# Next Milestones for `acgs-lite`

Last updated: 2026-05-16

This note keeps the near-term roadmap visible and concrete. It is intentionally short.

## v2.10.1 — shipped 2026-05-16

All planned items are complete.

- [x] EU AI Act deadline wording corrected to "main high-risk obligations: August 2, 2026" across CLI, templates, compliance module, PDF/Markdown reports, and docs
- [x] MCP server `validate(strict=False)` contract documented; concurrent callers share engine safely
- [x] Performance figures replaced with workload-dependent language (README, architecture docstrings, integration dashboard)
- [x] `docs/why-governance.md` MACI guarantee language tightened to reflect structural enforcement
- [x] `test_server_api_key_auth` env bleed fixed via `monkeypatch.delenv`

## v2.10.0 — shipped 2026-04-24

All planned items are complete.

- [x] Wire the hero demo image block in README (live `<img>` → `docs/assets/basic-governance-hero.gif`)
  - **Correction (2026-05-31):** the GIF asset itself was never produced — `docs/assets/` does not yet exist. Only the README image block was wired. The hero GIF is an open P1 blocker tracked in [`growth-execution-plan.md`](growth-execution-plan.md) §2.
- [x] Launch public burst — v2.10.0 tagged, release notes published
- [x] Tighten repo credibility signals — issue/PR hygiene, concrete release notes, canonical three-step proof path in README and examples
- [x] Publish technical walkthrough — blocked-action demo, audit trail, and MCP governance server paths all documented in `examples/`
- [x] Learn from first external feedback — README clarity, first-run demo friction, and integration priorities addressed in v2.9.0–v2.10.0 sprint

## v2.11.0 — next milestone (planned)

Items under consideration for the next release:

- Stabilize the lifecycle HTTP API (promote from Beta to Stable, add OpenAPI schema validation tests)
- Publish `acgs-lite-rust` to PyPI (wheel build CI is wired; tag push needed after confirming `wheels.yml`)
- Improve first-run ergonomics: `acgs init` scaffolding for the most common agent frameworks
- Address any feedback from the v2.10.0 public burst (HN / Reddit / X comments → targeted doc or API fixes)
- Evaluate promoting `GovernanceStream` and `PolicyStorage` interfaces from Experimental to Beta

## Canonical proof path

The first experience with `acgs-lite` should stay:
1. block an unsafe action
2. inspect the audit evidence
3. run governance as shared infrastructure

## Definition of progress

Real progress means more people can:
- understand the wedge quickly
- run the first demo successfully
- see why `acgs-lite` is different from generic guardrails
- trust that the repo is active and credible
