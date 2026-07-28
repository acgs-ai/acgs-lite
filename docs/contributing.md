# Contributing

Full contribution guidelines are in
[CONTRIBUTING.md](https://github.com/acgs-ai/acgs-lite/blob/main/CONTRIBUTING.md).

## Quick Summary

1. Fork the repository and create a feature branch
2. Install dev dependencies: `pip install -e ".[dev]"`
3. Write tests first (TDD): `python -m pytest tests/ -v --import-mode=importlib`
4. Run linting: `ruff check .`
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

!!! note "No API keys required"
    All tests use `InMemory*` stubs. Set placeholder keys to silence import-time checks:
    `export OPENAI_API_KEY=test-key-for-unit-tests`

## License

ACGS is licensed under Apache-2.0. See the
[LICENSE](https://github.com/acgs-ai/acgs-lite/blob/main/LICENSE) for details.
