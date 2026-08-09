# Blockers

Known durable blockers that require explicit owner action.

| Blocker | Owner | Impact | Next action |
| --- | --- | --- | --- |
| nltk CVE-2026-54293 (Dependabot #24, HIGH) | Upstream (nltk) | `nltk==3.9.4` in `requirements-dev.txt` is flagged by GHSA-p4gq-832x-fm9v (`nltk.data.load()` URL-encoded path traversal → arbitrary local file read). No patched release exists yet (`<= 3.9.4` all affected). Triage: nltk is a **transitive dev-only dependency** (pulled by `llama-index-core`); acgs-lite source never imports nltk (enforced by `tests/test_lazy_imports.py` heavy-prefix guard) and never calls `nltk.data.load()`, and nltk is absent from published package dependencies — exposure is limited to developer machines running third-party code paths that load `nltk:` URLs from untrusted input. | Bump the pin the moment upstream publishes a patched release; until then owner may dismiss the alert as "vulnerable code is not actually used" with a pointer to this row. |

## Local environment notes

A local shell may lack `make`, `build`, `mypy`, `mkdocs`, or a working virtualenv. This is not a project-owned blocker: run `make setup` (or `python3 -m pip install -e ".[dev]"` in a prepared environment), then rerun `make verify`.

## Resolved

| Blocker | Resolved | How |
| --- | --- | --- |
| PyPI publish token | 2026-07-28 | Superseded by PyPI trusted publishing. `.github/workflows/publish.yml` runs on a published GitHub Release and authenticates via OIDC (`id-token: write`, `pypi` environment), so no `TWINE_PASSWORD` is stored or renewed. Creating the release remains owner-gated. |
| No committed Python lockfile | 2026-06-01 | Committed `requirements-dev.txt` (pinned dev environment, `pip freeze --exclude-editable`). A full `uv.lock` is deferred — resolving the `all` extra's heavy ML deps (crewai/autogen/swarms) is too slow/network-bound to lock in this environment; revisit when locking the optional extras is feasible. |
