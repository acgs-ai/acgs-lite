# Contributing

Full contribution guidelines are in
[CONTRIBUTING.md](https://github.com/acgs-ai/acgs-lite/blob/main/CONTRIBUTING.md).

## Quick Summary

1. Fork the repository and create a feature branch
2. Install dev dependencies: `pip install -e ".[dev]"`
3. Write tests first (TDD): `python -m pytest tests/ -v --import-mode=importlib`
4. Run the repository gate: `make verify`
5. Submit a pull request with conventional commit messages

## Commit Format

```
<type>: <description>
```

Types: `feat`, `fix`, `refactor`, `chore`, `test`, `ci`, `docs`

## Testing

```bash
make test          # full suite
make test-quick    # skip slow tests
make test-cov      # with coverage report
```

!!! note "Test environment"
    Unit tests use stubs and mocks rather than live provider credentials. Optional
    integration tests still need their SDK dependencies. The Makefile sets placeholder
    OpenAI and Anthropic keys for tests; use its setup and verification commands to
    reproduce the repository environment.

## License

ACGS is licensed under Apache-2.0. See the
[LICENSE](https://github.com/acgs-ai/acgs-lite/blob/main/LICENSE) for details.

## Documentation and community content

Use the [installation catalog](installation.md) when documenting optional extras.
Keep published-release examples distinct from source-only APIs. Include the command,
observed result, and limitations in [community walkthroughs](community/share-a-walkthrough.md).

```bash
python -m mkdocs build --strict
python scripts/check_links.py
```

A successful local documentation build is ready for review; website publication
requires its own delivery and verification steps.
