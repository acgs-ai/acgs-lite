# GitHub Comment `FENCEABLE` Reference Provider

Demonstrates ACGS-Lite 4.x **Receipted Effects** for idempotent GitHub issue/PR comments with embedded `<!-- acgs-effect-key: ... -->` markers and atomic timeout fencing via a stateful fencing proxy (`GitHubFencingProxyServer` + `GitHubFencingProxyTransport`). Direct `api.github.com` endpoints are refused fail-closed because GitHub's native REST API does not expose an atomic `/comments/fence` primitive.

## Quickstart (Offline)

```bash
PYTHONPATH=src:. python -m examples.github_fenceable_provider
pytest tests/test_github_provider_conformance.py -v
```

## Optional Fencing Proxy Mode

Set `ACGS_GITHUB_PROXY_URL` (HTTPS required for non-localhost proxies) and `ACGS_GITHUB_PROXY_TOKEN` to exercise `GitHubFencingProxyTransport` end-to-end against a stateful fencing proxy:

```bash
ACGS_GITHUB_PROXY_URL=https://gh-proxy.example.test ACGS_GITHUB_PROXY_TOKEN=tok PYTHONPATH=src:. python -m examples.github_fenceable_provider
```
