# Blockers

Known durable blockers that require explicit owner action.

| Blocker | Owner | Impact | Next action |
| --- | --- | --- | --- |
| PyPI publish token | Project owner | `make publish` cannot run without `TWINE_PASSWORD`; release artifacts can still be built and checked locally. | Owner provides a valid token and explicit publish authorization. |

## Local environment notes

A local shell may lack `make`, `build`, `mypy`, `mkdocs`, or a working virtualenv. This is not a project-owned blocker: run `make setup` (or `python3 -m pip install -e ".[dev]"` in a prepared environment), then rerun `make verify`.

## Resolved

| Blocker | Resolved | How |
| --- | --- | --- |
| No committed Python lockfile | 2026-06-01 | Committed `requirements-dev.txt` (pinned dev environment, `pip freeze --exclude-editable`). A full `uv.lock` is deferred — resolving the `all` extra's heavy ML deps (crewai/autogen/swarms) is too slow/network-bound to lock in this environment; revisit when locking the optional extras is feasible. |
