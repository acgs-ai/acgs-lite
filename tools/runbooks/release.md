# Runbook: Release

Goal: publish the exact artifacts built and tested from an approved source.
Agent: `release` (see `agents/release.agent.yaml`). Publication requires explicit
owner authorization; local verification is not release authorization.

## Prepare and review

1. Run `make verify` and `ruff format --check src/acgs_lite tests scripts`.
2. Update both `pyproject.toml` (`project.version`) and
   `src/acgs_lite/_meta.py` (`VERSION`). Follow SemVer; stable breaking changes
   require a major version and migration guidance.
3. Date the changelog entry and update its compare links. Before creating the
   tag, run `python scripts/check_release_coherence.py --no-require-current-tag`.
4. Run `make publish-dry-run` and verify the wheel in a fresh environment.
   Record source identity, artifact hashes, test results and independent review.
5. Submit the candidate through the repository review process, wait for CI,
   then merge the reviewed changes into `main`. Any changes invalidate affected
   checks and require fresh evidence.

## Qualify the release artifacts

After separate authorization for tagging, qualification and publication:

1. Create a new `vX.Y.Z` tag for the approved commit in `main` history. Never move
   or reuse an existing release tag or PyPI version. Confirm both version files
   match the tag and run `python scripts/check_release_coherence.py`.
2. Dispatch `.github/workflows/release-candidate.yml` on that exact tag with
   `source_ref=refs/tags/vX.Y.Z`. The workflow must already exist on `main`.
3. Wait for the complete workflow to succeed. It tests the optional bridge with
   explicit `crypto` dependencies, builds wheel and sdist once, tests the exact
   installed wheel including real Lean checks, and runs source coverage gates.
4. Inspect the `acgs-lite-release-candidate-<run-id>` artifact. It contains
   `candidate.json`, the distributions and their qualification evidence. Verify
   the source SHA, version, distribution hashes, nonempty test groups and review
   correspondence. A failed or stale run is not publishable evidence.

## Publish the qualified artifacts

Dispatch `.github/workflows/publish.yml` with the successful `candidate_run_id`
and matching `tag`. Qualification must be less than 24 hours old. The workflow
checks repository, workflow, run attempt, source, tag ancestry, evidence and
artifact hashes before uploading through PyPI trusted publishing (OIDC).
It does not rebuild distributions. Publishing a GitHub Release is not this
workflow's trigger.

After success, read PyPI's version metadata and compare both uploaded SHA-256
digests with `candidate.json`. Install the published wheel in a fresh environment
and run the package examples. Record the actual upload and verification result;
do not equate it with independent production qualification.

## Failure handling

- If local tests, formatting or metadata fail, fix them before pushing.
- If the version already exists, prepare a new version and requalify it; never
  overwrite or delete the old release to reuse its name.
- If source, tag, run or artifact identity differs, stop publication and build
  fresh evidence for the intended source.
- If trusted publishing or environment approval is unavailable, report the
  blocker. Do not replace the workflow with a local token upload to bypass gates.
- If upload status is uncertain, inspect PyPI before retrying; do not report
  success or create another artifact based only on a timeout.
