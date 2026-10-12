# Community

Help make governed execution easier to understand, reproduce, and test. Start
with a small example, a clear question, or a concrete correction to a guide.

<div class="grid cards" markdown>

- **Ask or compare approaches**

    Describe your framework, the action being governed, and the result you need.

    [Q&A discussions](https://github.com/acgs-ai/acgs-lite/discussions/categories/q-a) · [FAQ](community/faq.md)

- **Report a reproducible bug**

    Include the package version or commit, minimal code, and expected behavior.

    [Open an issue](https://github.com/acgs-ai/acgs-lite/issues/new/choose)

- **Improve the project**

    Fix a confusing instruction, add a focused regression test, or document an adapter.

    [Contributing](contributing.md) · [Adding an integration](contributing-integrations.md)

- **Share a walkthrough**

    Show the allowed path, denied path, and evidence that the boundary was reached.

    [Walkthrough guide](community/share-a-walkthrough.md) · [Show and tell](https://github.com/acgs-ai/acgs-lite/discussions/categories/show-and-tell)

</div>

## Choose the right place

| What you need | Where to go | What to include |
| --- | --- | --- |
| Setup or API question | [Discussions](https://github.com/acgs-ai/acgs-lite/discussions) | Version, Python version, selected extras, and a small example |
| Incorrect result or broken documentation | [Issues](https://github.com/acgs-ai/acgs-lite/issues) | Expected versus actual result and a reproducible command |
| Proposed behavior change | [Issues](https://github.com/acgs-ai/acgs-lite/issues) | Problem, affected execution path, and acceptance criteria |
| Suspected vulnerability or authorization bypass | [Security policy](security.md) | Report privately; avoid publishing an exploit or sensitive trace in an issue |
| Tested example or experience report | [Discussions](https://github.com/acgs-ai/acgs-lite/discussions) | Reproduction steps, results, and limits following the walkthrough guide |

## Useful first contributions

- Reproduce the [5-minute membrane](guides/five-minute-membrane.md) in a clean environment
  and report any mismatch between the instructions and the installed artifact.
- Improve one adapter example using the [integration decision guide](integration-decision-guide.md).
- Add a negative-path regression that proves a denied callable was never invoked.
- Explain one operational limit, such as stream output validation or audit persistence.

Use [Ideas](https://github.com/acgs-ai/acgs-lite/discussions/categories/ideas) to
discuss a possible feature before turning it into a scoped issue.
Search existing issues before filing a new one. Keep discussion respectful and
specific; the repository's [Code of Conduct](https://github.com/acgs-ai/acgs-lite/blob/main/CODE_OF_CONDUCT.md)
and [project governance](https://github.com/acgs-ai/acgs-lite/blob/main/GOVERNANCE.md)
describe participation and decisions.

## Evidence before claims

Label reports as local tests, simulations, CI results, or deployment observations.
Identify the version and environment. A working demo is useful without calling it
production-ready, certified, or independently adopted. Do not share private prompts,
credentials, personal data, or customer audit logs in a public report.

These pages provide contribution paths and content templates. They do not assert
an existing user community, independently confirmed production users, or a support SLA.
