# Runbook: Release

Goal: produce a clean, validated release artifact and verify it installs from a fresh
environment. Agent: `release` (see `agents/release.agent.yaml`).

> Uploading to PyPI is **owner-gated**, but it is no longer a manual `twine` step.
> Publishing is performed by `.github/workflows/publish.yml` when a GitHub Release is
> published, authenticated with PyPI trusted publishing (OIDC) — no `TWINE_PASSWORD`
> token is involved. The owner-gated action is *creating the release*.

## Steps

```bash
# 1. Make sure everything is green and consistent.
make verify

# 2. Bump the version in BOTH places — the publish workflow fails if the tag
#    and pyproject disagree.
$EDITOR pyproject.toml            # project.version
$EDITOR src/acgs_lite/_meta.py    # VERSION

# 3. Update the changelog: date the new version's heading and add its
#    compare link at the bottom of the file.
$EDITOR CHANGELOG.md

# 4. Build + validate the package (no upload).
make publish-dry-run        # = make build && twine check dist/*

# 5. Confirm the release state is coherent once the tag exists.
python scripts/check_release_coherence.py
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

Merge the release commit to `main`, then publish a GitHub Release whose tag is
`vX.Y.Z` — matching `pyproject.toml` exactly. That tag creation is what publishes
the package; `Publish to PyPI` builds the sdist and wheel, runs `twine check`, and
uploads through trusted publishing.

## Failure modes

| Symptom | Fix |
| --- | --- |
| `twine check` fails | fix packaging metadata in `pyproject.toml` |
| fresh install import error | a runtime dep is under an optional extra — move it to `dependencies` |
| publish workflow fails on the version check | the release tag does not match `pyproject.toml`; delete the release + tag, correct the version, re-release |
| publish workflow does not run | the release was saved as a draft — it triggers on `published`, not `created` |
