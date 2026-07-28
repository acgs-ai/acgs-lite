# Governance

This document describes how the `acgs-lite` project is run: the roles people hold,
how someone moves between them, and how decisions get made. It is intentionally
lightweight for the project's current stage and will harden as the community grows.

## Current stage

`acgs-lite` is **founder-led** today, transitioning toward a **meritocratic** model as
external contributors establish a track record. The roles below describe the ladder we
are building toward; we promote people into them as the work warrants, not on a fixed
schedule.

## Roles and the contribution ladder

Contribution is a ladder. Each rung is earned through sustained, quality work — not
tenure. Movement is in both directions: inactivity can step a role back, and that is not
a judgment, just a reflection of current involvement.

### 1. Contributor

Anyone who opens an issue, a pull request, improves docs, answers a question in
Discussions, or files a good bug report.

- **How to start:** pick a [`good first issue`](https://github.com/acgs-ai/acgs-lite/labels/good%20first%20issue), comment that you're taking it, open a PR. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- **No permissions needed** — fork and PR.

### 2. Reviewer

A contributor with a track record of quality PRs who is trusted to review others' work
in one or more subsystems (e.g., integration adapters, compliance mappings, docs).

- **How you get here:** ~3–5 merged, high-quality PRs **and** helpful review comments on others' PRs, in a focused area.
- **What you can do:** review and approve PRs in your area; triage and label issues; your approval counts toward merge.
- **How it's granted:** an existing maintainer proposes you; promotion is by maintainer consensus, announced in Discussions.

### 3. Maintainer

A reviewer trusted with the health of the project: merge rights, release authority for
their area, and a say in direction.

- **How you get here:** sustained reviewer-level contribution, good judgment on scope and
  the project's [fail-closed](README.md#-safety-defaults) safety principles, and reliability over time.
- **What you can do:** merge PRs, cut releases, shape the roadmap, mentor contributors, vote on decisions.
- **Responsibilities:** uphold the response-time commitments in `CONTRIBUTING.md`, mentor
  new contributors warmly, and keep the project's safety guarantees intact.
- **How it's granted:** proposed by an existing maintainer, decided by maintainer consensus.

The current maintainer is [@dislovelhl](https://github.com/dislovelhl).

## Decision-making

We prefer **lazy consensus**: a proposal (issue, PR, or Discussion) that draws no
sustained objection within a reasonable window (typically 3–5 days for non-trivial
changes) is considered accepted.

- **Routine changes** (bug fixes, tests, docs, new adapters/templates that follow existing patterns): one maintainer/reviewer approval is enough.
- **Significant changes** (public API, the [matcher hot path](CLAUDE.md), MACI enforcement semantics, security defaults, governance itself): require explicit maintainer consensus and an open discussion period. These are also the changes most likely to touch our safety guarantees, so we err on the side of more review.
- **Disagreement:** if consensus can't be reached, the matter is decided by a simple
  majority of maintainers; the founder breaks ties while the project remains founder-led.

All non-trivial decisions happen in the open — GitHub Issues, PRs, or
[Discussions](https://github.com/acgs-ai/acgs-lite/discussions) — so the reasoning is
preserved for newcomers.

## Non-negotiables

Some properties are foundational and not subject to ordinary lazy consensus — changing
them requires explicit, documented maintainer consensus:

- **Fail-closed by default.** See [Safety Defaults](README.md#-safety-defaults).
- **MACI separation of powers** is not bypassed in wrappers or integrations.
- **Tamper-evident audit trail** integrity is preserved.
- **Apache-2.0 license** and inbound-licensing terms in `CONTRIBUTING.md`.

## Security

Security issues do **not** go through public issues or this process. Follow
[`SECURITY.md`](SECURITY.md) for responsible disclosure.

## Code of Conduct

All participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Changing this document

Governance changes are a "significant change": propose via PR, allow an open discussion
period, and require maintainer consensus to merge.
