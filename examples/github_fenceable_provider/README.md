# GitHub Comment `FENCEABLE` Reference Provider

Demonstrates ACGS-Lite 4.x **Receipted Effects** for idempotent GitHub issue/PR comments with embedded `<!-- acgs-effect-key: ... -->` markers and atomic timeout fencing.

## Quickstart (Offline)

```bash
PYTHONPATH=src:. python -m examples.github_fenceable_provider
pytest tests/test_github_provider_conformance.py -v
```

## Optional Live Test Mode

Set `ACGS_GITHUB_TEST_URL` (HTTPS required for non-localhost endpoints) and `ACGS_GITHUB_TEST_TOKEN` to exercise `LiveGitHubTransport` end-to-end:

```bash
ACGS_GITHUB_TEST_URL=https://api.example.test ACGS_GITHUB_TEST_TOKEN=tok PYTHONPATH=src:. python -m examples.github_fenceable_provider
```
