# Upstream Strategy

Plan for promoting this example into the upstream
[arize-phoenix](https://github.com/Arize-ai/phoenix) repository as a
**docs-only** contribution. No changes to Phoenix core code are required
or proposed.

## Target

- **Repo**: `arize-phoenix`
- **Path**: `docs/tutorials/integrations/acgs-lite-governance.md`
- **Form**: a single tutorial page that renders this example end-to-end
  using a published `acgs-lite` wheel from PyPI.

## Scope

| In scope | Out of scope |
| --- | --- |
| New tutorial markdown file | Phoenix core SDK changes |
| Code blocks copied from this example | New Phoenix attribute conventions |
| Screenshots of the resulting Phoenix UI views | Vendor branding outside the tutorial |
| A short "what is governance telemetry" intro | New OTel semantic-convention proposals |

The tutorial introduces two namespaces — generic `governance.*` and
vendor `acgs.*` — and is explicit that **only the generic half is a
candidate for future cross-vendor convention work**. The vendor half is
clearly labelled as such.

## Prerequisite: ship a wheel first

The upstream tutorial must run from `pip install acgs-lite` using a
published wheel — not a local editable install. Concretely, before the
upstream PR is opened:

1. `acgs-lite` package is published to PyPI at the version the tutorial
   pins.
2. The tutorial's `pip install` line resolves successfully on a clean
   Python 3.10+ environment with no network access to GitHub.
3. The example here runs end-to-end against the published wheel (not
   `pip install -e ../../`).

This is non-negotiable — Phoenix maintainers will not merge a tutorial
that depends on a local editable install.

## Maintainer Pushback Pre-Mortem

Three plausible objections, each with a counter:

### "We don't want vendor integrations in core docs."

**Counter**: this is observability enhancement, not a vendor lock-in.
Phoenix already publishes tutorials for OpenAI, Anthropic, LlamaIndex,
LangChain, DSPy, and others. ACGS-lite is plain OTel-emitting Python; it
adds zero coupling to Phoenix internals and ships entirely from PyPI.
The tutorial requires no changes to Phoenix and can be removed without
side effects.

### "`acgs.*` namespace is vendor-specific."

**Counter**: agreed — and explicitly documented as such in
`GOVERNANCE_ATTRIBUTES.md`. The `governance.*` namespace is generic and
designed for cross-vendor adoption; only the `acgs.*` half (receipt id,
fail-closed flag, review outcome) is vendor-tagged. We propose merging
the tutorial as-is, then proposing the `governance.*` half as a
cross-vendor semantic convention in a follow-up if interest exists.

### "This couples Phoenix to governance semantics."

**Counter**: it does not. Phoenix sees plain OTLP span attributes —
identical in shape to attributes set by the OpenAI instrumentor, the
LangChain tracer, or any other tutorial integration. There is no
Phoenix-side parser, no plugin, no special handler. If a user removed
the `acgs-lite` import the rest of Phoenix would behave identically.

## Contribution Sequencing

```
[ now ]   Local example with editable install  ← we are here
   ↓
[ next ]  Publish acgs-lite to PyPI (or cut new release)
   ↓
[ next ]  Run the example end-to-end on a clean machine using
           pip install acgs-lite (no editable, no GitHub)
   ↓
[ next ]  Publish a polished version on docs.acgs.ai (vendor docs)
           with screenshots & narrative — this becomes the primary
           reference even after upstream merges
   ↓
[ next ]  Open a docs PR to arize-phoenix linking to the vendor page
           and inlining the minimal tutorial body. Pre-mortem above
           is anchored in the PR description.
```

This sequencing keeps the cost of "no, thanks" low: if Phoenix
maintainers reject the upstream PR, the vendor docs page remains the
canonical reference and users can find it via the standard search
surface.
