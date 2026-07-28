# Contributing: Building the Future of AI Governance

**Meta Description**: Join the ACGS-Lite community. Learn how to contribute new compliance mappings, integration adapters, and core engine improvements using our 2026-ready development workflow.

---

Thank you for your interest in contributing to ACGS-Lite! We are building the foundational infrastructure for safe, autonomous AI, and we welcome contributions from developers, security researchers, and policy experts.

## 🚦 New here? Start in 15 minutes

1. Find a [`good first issue`](https://github.com/acgs-ai/acgs-lite/labels/good%20first%20issue) — each is scoped to be completable by a newcomer in under a day, with full context in the issue body.
2. Comment on it to claim it (no need to ask permission for `good first issue`s — just say you're on it).
3. Set up your environment (below), make the change with a test, open a PR.
4. Have a question first? Open a [Discussion](https://github.com/acgs-ai/acgs-lite/discussions) — no question is too small.

## 🤝 Our commitment to you

We take first contributions seriously. When you open your first issue or PR:

- We aim to give a **first response within 2 business days** — even if it's just "thanks, reading this, will reply properly by <date>."
- Every PR gets constructive, specific feedback. We won't ignore your work or demand sweeping changes without explanation.
- Small, well-scoped PRs are welcome and reviewed fastest. You do not need to solve everything in one PR.

**Minimum viable maintenance (honest expectations):** this is a small project. We prioritize security reports, correctness bugs in stable components, and first-time-contributor PRs. Large feature proposals are best raised as a Discussion *before* you write code, so we can align on scope and you don't waste effort.

## 🪜 The contribution ladder

Contribution is a ladder you climb through sustained quality work: **contributor → reviewer → maintainer**. Full role definitions, how promotions happen, and how decisions are made are in [`GOVERNANCE.md`](GOVERNANCE.md). The short version: open good PRs, help review others' work, and trust accrues.

## 🏗️ What to Contribute

We are particularly looking for contributions in these areas:
1.  **Compliance Frameworks**: Mapping new regional or industry regulations (e.g., Canadian AIDA, Japan AI Guidelines) to ACGS rule templates.
2.  **Integration Adapters**: Adding support for new AI frameworks or tool ecosystems (e.g., PydanticAI, Swarms, Magentic).
3.  **Formal Verification**: Improving our Z3 and Lean 4 verification modules.
4.  **Documentation**: Use cases, tutorials, and security best practices.

## 🛠️ Development Setup

ACGS-Lite is a Python 3.10+ project. We use `ruff` for linting and `pytest` for testing.

```bash
# 1. Clone the repo
git clone https://github.com/acgs-ai/acgs-lite.git
cd acgs-lite

# Option A — uv workspace (recommended, matches CI exactly)
uv sync --all-extras           # first-time: installs the locked venv
uv run make test-quick         # runs tests inside the locked venv

# Option B — standalone venv (standalone/offline use)
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev,mcp,all]"
make test-quick
```

**Note**: All tests use `InMemory` stubs. You do **not** need live API keys for OpenAI or Anthropic to run the test suite. Any placeholder value (e.g. `OPENAI_API_KEY=test-key`) is sufficient — see `.env.example`.

## 🧪 Testing Policy (TDD)

We follow a strict **Test-Driven Development** workflow. Every feature or fix must be accompanied by tests.
*   **Location**: All tests go in the `tests/` directory.
*   **Stubs**: Use the `InMemoryAuditBackend` and `InMemoryGovernanceEngine` patterns to keep tests fast and deterministic.
*   **Coverage**: We target **80%+ coverage** for the core engine and **70%+** for integration adapters.

## 📏 Coding Standards

- **Explicit Typing**: Use Python 3.10+ type hints (`X | Y` instead of `Union[X, Y]`).
- **Async First**: All I/O-bound integrations (network calls, file writes) must be `async`.
- **Fail-Closed**: Always design for the "worst-case" failure. If a check fails to run, it must block the action.
- **Line Length**: 100 characters (enforced by Ruff).

## 🚢 Pull Request Process

1.  **Fork** the repository.
2.  Create a **Feature Branch** (`git checkout -b feat/my-new-feature`).
3.  Implement your changes and add tests.
4.  Run the verification suite:
    ```bash
    uv run make lint
    uv run make typecheck
    uv run make test-cov
    # or with the standalone venv active:
    # make lint && make typecheck && make test-cov
    ```
5.  Submit your PR with a **Conventional Commit** message (e.g., `feat: add NIST AI RMF mapping`).

## 🛡️ Security Disclosures

If you find a security vulnerability, please do **not** open a public issue. Instead, follow our [Security Policy](SECURITY.md) to report it responsibly.

## 📜 License

By contributing to ACGS-Lite, you agree that your contributions will be licensed under the **Apache-2.0 License**.
