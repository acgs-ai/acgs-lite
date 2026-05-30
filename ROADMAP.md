# Roadmap

This is the public, at-a-glance view of where `acgs-lite` is going. It exists so contributors
and users can see the project is alive and directed, and find the best place to help.

## How the roadmap is organized

| Horizon | Document | What it covers |
| --- | --- | --- |
| **Product / releases** | [`planning/next-milestones.md`](planning/next-milestones.md) | Shipped releases and the next version's planned work (API stability, features). |
| **Community** | [`planning/community-roadmap.md`](planning/community-roadmap.md) | How we grow contributors, channels, governance, and engagement. |
| **Governance** | [`GOVERNANCE.md`](GOVERNANCE.md) | Roles, the contribution ladder, and how decisions are made. |

## Right now

- **Current release:** see [`CHANGELOG.md`](CHANGELOG.md) and [`planning/next-milestones.md`](planning/next-milestones.md).
- **Stable core:** `GovernanceEngine`, `Constitution`, MACI role separation, `AuditLog`, `GovernedAgent`, and the OpenAI / Anthropic / LangChain adapters. See the Component Stability table in [`README.md`](README.md#️-component-stability).
- **Beta / Experimental:** lifecycle HTTP API, 18-framework compliance mapping, Z3 / Lean formal verification — clearly marked in the README.

## Where help is most welcome

The highest-leverage contributions right now, in rough priority order:

1. **Integration adapters** for agent frameworks we don't cover yet (e.g. Swarms, smolagents, Semantic Kernel).
2. **Compliance framework mappings** for new regions (e.g. Japan AI Guidelines, Korea, Brazil).
3. **Examples** for adapters that ship without one, so newcomers can copy a working starting point.
4. **Docs**: "what to use when" guides, FAQ-style openers, and tutorials.
5. **Test coverage** for integration adapters (target: 70%+).

See the [`good first issue`](https://github.com/dislovelhl/acgs-lite/labels/good%20first%20issue) and
[`help wanted`](https://github.com/dislovelhl/acgs-lite/labels/help%20wanted) labels for concrete, scoped tasks,
and [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to get started.

## Proposing roadmap changes

Have an idea for a direction not listed here? Open a
[Discussion](https://github.com/dislovelhl/acgs-lite/discussions) in the **Ideas** category. Significant
direction changes follow the decision process in [`GOVERNANCE.md`](GOVERNANCE.md).
