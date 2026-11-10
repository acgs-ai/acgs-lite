# Releasing acgs-lite

This runbook is for maintainers who publish `acgs-lite` to PyPI. A release is two
manually dispatched GitHub Actions workflows:

1. [`release-candidate.yml`](https://github.com/acgs-ai/acgs-lite/blob/main/.github/workflows/release-candidate.yml)
   builds the wheel and sdist once, qualifies them, and uploads them as a run artifact.
2. [`publish.yml`](https://github.com/acgs-ai/acgs-lite/blob/main/.github/workflows/publish.yml)
   downloads that artifact, re-verifies it, and uploads the same files to PyPI
   without rebuilding.

`make publish` exits 1 on purpose. Do not upload from a local build: that breaks
the link between the qualified files and the published ones.

In the commands below, replace `X.Y.Z` with the version (for example `4.0.0`) and
`RUN_ID` with the numeric run ID of the candidate run.

## 1. Check the preconditions

Do all of these on the `main` commit you intend to release.

1.  **CI is green on that `main` commit.** Neither release workflow checks this,
    so look at the CI run for the commit yourself.
2.  **The version is set.** `pyproject.toml` has `version = "X.Y.Z"` and
    `src/acgs_lite/_meta.py` has `VERSION = "X.Y.Z"`. `publish.yml` refuses a tag
    that differs from the `pyproject.toml` version.
3.  **The changelog is ready.** `CHANGELOG.md` has a dated
    `## [X.Y.Z] - YYYY-MM-DD` heading with the release notes and an empty
    `## [Unreleased]` section above it.
4.  **The version is not on PyPI yet.** This must print `404`:

    ```bash
    curl -s -o /dev/null -w '%{http_code}\n' https://pypi.org/pypi/acgs-lite/X.Y.Z/json
    ```

    A PyPI version number can never be reused, even after deleting files.
5.  **The README is final.** `pyproject.toml` uses `README.md` as the PyPI long
    description, so the README at the tagged commit becomes the PyPI page for
    `X.Y.Z` and cannot be changed afterwards. Before tagging, make sure its install
    pins (`pip install acgs-lite==...`) and its "Current status" lines are correct
    for `X.Y.Z`.
6.  **Dependents still work.** The candidate run installs the source checkout as
    `.[crypto]` with `gove-zone==1.0.0rc2` and runs `tests/gove`, and installs the
    built wheel with `gove-zone==1.0.0rc2` for wheel qualification. Check any other
    dependent projects yourself before you tag.
7.  **Protected-path changes are authorized.** `pyproject.toml` is a protected
    path in `.github/immutable-core-policy.json`. A PR that changes it (for
    example the version bump) needs a maintainer listed in that policy to
    dispatch `immutable-core-authorize.yml` on `main` with the exact PR number,
    current `main` SHA and reviewed PR head SHA, and then to re-run the guard
    with the same values:

    ```bash
    gh workflow run immutable-core-authorize.yml --repo acgs-ai/acgs-lite --ref main \
      -f pr_number=PR_NUMBER -f base_sha=MAIN_SHA -f head_sha=PR_HEAD_SHA
    gh workflow run immutable-core-guard.yml --repo acgs-ai/acgs-lite --ref main \
      -f pr_number=PR_NUMBER -f base_sha=MAIN_SHA -f head_sha=PR_HEAD_SHA
    ```

## 2. Tag the release commit

Merge the release-prep PR first, then tag the `main` commit you checked in step 1
(`RELEASE_SHA` below). The tag must be named `vX.Y.Z`, and its commit must be an
ancestor of `origin/main` when you publish.

```bash
git fetch origin main --tags
git merge-base --is-ancestor RELEASE_SHA origin/main && echo "on main"
git tag -a vX.Y.Z RELEASE_SHA -m "acgs-lite X.Y.Z"
git push origin vX.Y.Z
```

Then confirm the changelog and tags agree:

```bash
python scripts/check_release_coherence.py
```

It prints `OK: release state is coherent` once the dated `X.Y.Z` heading has a
matching `vX.Y.Z` tag. Before the tag exists it reports an incoherence for the
dated heading; that is expected between merging the prep PR and tagging.

## 3. Qualify the candidate on the tag

Dispatch the candidate workflow **on the tag**, with `source_ref` set to the same ref:

```bash
gh workflow run release-candidate.yml --repo acgs-ai/acgs-lite \
  --ref vX.Y.Z -f source_ref=refs/tags/vX.Y.Z
```

The workflow fails unless `source_ref` equals the ref it was dispatched on
(`$GITHUB_REF`), and it accepts only `refs/heads/main` or `refs/tags/v*`. A
candidate dispatched on `main` qualifies but can never be published, because
`publish.yml` requires the candidate run's branch to equal the tag. Use a `main`
run only as a dry run.

Find the run ID and wait for it to finish:

```bash
gh run list --repo acgs-ai/acgs-lite --workflow release-candidate.yml --limit 5 \
  --json databaseId,headBranch,status,conclusion,createdAt
gh run watch RUN_ID --repo acgs-ai/acgs-lite --exit-status
```

Pick the run whose `headBranch` is `vX.Y.Z`.

### What the candidate run checks

1. **Gove compatibility** (Python 3.11, 3.12 and 3.13): installs `.[crypto]` with
   `gove-zone==1.0.0rc2` and runs `tests/gove`; it fails if no test ran, any was
   skipped, or any failed.
2. **Source identity**: the checkout is clean and `HEAD` equals the commit of
   `source_ref`.
3. **Build once**: `python -m build --wheel --sdist`, then `twine check`.
4. **Wheel qualification**: installs the single built wheel with `[z3,crypto]` and
   `gove-zone==1.0.0rc2` in a clean venv and runs `scripts/qualify_wheel.py
   --require-lean` with a pinned, checksum-verified Lean 4.34.0 toolchain.
5. **Source suite**: `pytest` on `tests/` with
   `-m "not slow and not benchmark and not e2e"`, at least 80% coverage, then
   `scripts/check_critical_coverage.py`.
6. **Evidence binding**: `scripts/release_candidate.py create` writes
   `candidate.json`, which records the source ref and SHA, the SHA-256 and size of
   the wheel, the sdist and every evidence file, and the SHA-256 and mode of every
   tracked or untracked, non-ignored file in the checkout (cache and build
   directories excluded).
   `release_candidate.py verify` then re-checks the assembled directory.
7. **Upload**: artifact `acgs-lite-release-candidate-RUN_ID`, kept for 14 days.

## 4. Publish within 24 hours

Dispatch the publish workflow with the candidate run ID and the tag:

```bash
gh workflow run publish.yml --repo acgs-ai/acgs-lite --ref main \
  -f candidate_run_id=RUN_ID -f tag=vX.Y.Z
```

Publishing must happen within 24 hours of the candidate run's `created_at` time
(when the run started, not when it finished). The job runs in the `pypi`
environment, so it may wait for an environment approval.

### What the publish run checks

1. `candidate_run_id` is all digits, and `tag` matches the shell pattern
   `v[0-9]*.[0-9]*.[0-9]*` (a loose check; the exact check is step 3).
2. The candidate run (fetched from the GitHub API) is a completed, successful
   `workflow_dispatch` run of `.github/workflows/release-candidate.yml` in this
   repository, and its `head_branch` equals the tag.
3. The checked-out tag commit is an ancestor of `origin/main`, and the tag without
   its `v` equals the `pyproject.toml` version.
4. `scripts/release_candidate.py verify-publish` checks that:
   - the artifact digests, evidence digests and source-file hashes match the tag
     checkout;
   - every qualification status passed;
   - the source ref is `refs/tags/vX.Y.Z`;
   - the run ID, run attempt, workflow path, repository and `head_sha` match the
     fetched run;
   - the run is no older than 24 hours.
5. `https://pypi.org/pypi/acgs-lite/X.Y.Z/json` returns 404. A 200 stops the run
   ("overwrite is forbidden"); any other status or a network error also stops it.
6. Only the wheel and sdist named in `candidate.json`, with matching size and
   SHA-256, are staged and uploaded by `pypa/gh-action-pypi-publish`.

## 5. Verify the published release

```bash
python -m pip index versions acgs-lite
curl -s https://pypi.org/pypi/acgs-lite/json | python -c "import json,sys; print(json.load(sys.stdin)['info']['version'])"
```

Install it in a clean environment and check the reported version:

```bash
python -m venv /tmp/acgs-release-check
/tmp/acgs-release-check/bin/python -m pip install "acgs-lite==X.Y.Z"
/tmp/acgs-release-check/bin/python -m pip check
/tmp/acgs-release-check/bin/python -c "import acgs_lite; print(acgs_lite.__version__)"
```

Optionally confirm that PyPI serves the qualified files: download the candidate
artifact and compare its SHA-256 values with the `digests.sha256` values in
`https://pypi.org/pypi/acgs-lite/X.Y.Z/json`.

```bash
gh run download RUN_ID --repo acgs-ai/acgs-lite \
  -n acgs-lite-release-candidate-RUN_ID -D /tmp/acgs-candidate
sha256sum /tmp/acgs-candidate/*.whl /tmp/acgs-candidate/*.tar.gz
```

Afterwards, in a follow-up PR, update the install pins in `docs/quickstart.md` and
`docs/installation.md`, the note in `docs/index.md`, and the version placeholders
in the issue and discussion templates under `.github/`. (The README was fixed
before tagging; see step 1.)

## What cannot be undone

- A version number published to PyPI cannot be reused, even if you delete its
  files. If a release is bad, **yank** it on PyPI (project settings, release,
  "Yank") and publish a new patch version.
- `publish.yml` never overwrites: once PyPI answers 200 for `X.Y.Z`, the workflow
  refuses that version.

## When something fails

| Message or symptom | Cause | What to do |
| --- | --- | --- |
| `fetched run is stale or from the future` | More than 24 h since the candidate run started. | Re-dispatch `release-candidate.yml` on the same tag (step 3) and publish with the new run ID. No new tag is needed. |
| `candidate tag mismatch` | The candidate run was dispatched on a different ref (for example `main`), or `tag` is wrong. | Dispatch a candidate on `--ref vX.Y.Z` and use its run ID. |
| `untrusted candidate run <field>` | The run ID is not a completed, successful `workflow_dispatch` run of `release-candidate.yml`. | Check the run ID; wait for the candidate to finish successfully. |
| `publish metadata <field> mismatch` or `fetched run <field> mismatch` | The candidate evidence does not belong to this run, tag or repository. | Use the run ID of a candidate run dispatched on this tag. |
| `git merge-base --is-ancestor` step fails | The tag commit is not on `main`. | Nothing was published. Move the tag to a commit on `main` (delete and re-push it), then re-qualify. |
| The version comparison step fails | The tag does not equal the `pyproject.toml` version at that commit. | Nothing was published. Fix the version on `main`, move the tag to the fixed commit, then re-qualify. |
| `source manifest ...` or `artifact digest mismatch` | The tag checkout or downloaded files differ from what was qualified. | Re-qualify on the tag. |
| `Version X.Y.Z already exists on PyPI; overwrite is forbidden.` | The version is already published. | Do not retry. Publish a new version. |
| `Cannot confirm PyPI version availability.` or `Unexpected PyPI HTTP status` | PyPI could not be reached or answered oddly. | Re-run `publish.yml` with the same inputs while the candidate is under 24 h old. |
| Candidate qualification fails | A test, coverage or wheel check failed on the tagged commit. | Fix on `main` through a PR. The tag still points at the failing commit: if `X.Y.Z` is not on PyPI, move the tag to the fixed commit and re-qualify. |
