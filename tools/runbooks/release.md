# Runbook: Release

Goal: produce a clean, validated release artifact and verify it installs from a fresh
environment. Agent: `release` (see `agents/release.agent.yaml`).

> Uploading to PyPI (`make publish`) is **owner-gated** — it needs a valid `TWINE_PASSWORD`
> token. See `BLOCKERS.md` (PyPI token). Never run `make publish` without explicit owner
> authorization.

## Steps

```bash
# 1. Make sure everything is green and consistent.
make verify

# 2. Update the changelog for the new version.
$EDITOR CHANGELOG.md

# 3. Build + validate the package (no upload).
make publish-dry-run        # = make build && twine check dist/*
```

## Verify a clean install (fresh venv)

```bash
python3 -m venv /tmp/acgs-fresh && /tmp/acgs-fresh/bin/pip install dist/*.whl
/tmp/acgs-fresh/bin/python -c "import acgs_lite; print(acgs_lite.__version__)"
/tmp/acgs-fresh/bin/python examples/release_proof.py --output /tmp/acgs-release-proof.json
cat /tmp/acgs-release-proof.json
```

The release proof script is the canonical proof artifact for the current package line: it runs without API keys and emits a deterministic JSON summary that another developer can inspect locally.

## Publish (owner only)

```bash
TWINE_PASSWORD=*** make publish
```

## Failure modes

| Symptom | Fix |
| --- | --- |
| `twine check` fails | fix packaging metadata in `pyproject.toml` |
| fresh install import error | a runtime dep is under an optional extra — move it to `dependencies` |
| `403` on publish | token expired/missing — owner must renew (see `BLOCKERS.md`) |
