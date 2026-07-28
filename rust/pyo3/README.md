# acgs-lite-rust

Optional Rust accelerator for the [acgs-lite](https://github.com/acgs-ai/acgs-lite)
governance engine matcher, built with [PyO3](https://pyo3.rs/) and
[maturin](https://www.maturin.rs/).

## Relationship to `acgs-lite`

The main `acgs-lite` package is pure-Python for broad platform compatibility.
This companion wheel is **optional**: installing it speeds up the hot
validation path by ~5–20× for workloads dominated by regex matching, while
`acgs-lite` itself remains fully functional without it (the validator falls
back to the Python implementation).

```
acgs-lite            (pure-Python, always installable)
acgs-lite-rust       (optional, this crate — ships as abi3 wheels)
```

## Installation

End-users typically install both from PyPI:

```bash
pip install acgs-lite acgs-lite-rust
```

`acgs-lite` will detect the rust module at import time and switch the
validator hot-path over automatically.

## Building wheels locally

```bash
pip install maturin
cd rust/pyo3
maturin develop         # in-place install for local testing
maturin build --release # produce a wheel in ../target/wheels/
```

## Building release wheels

Release wheels for manylinux (x86_64, aarch64), macOS (x86_64, arm64), and
Windows (x86_64) are produced by
[`.github/workflows/wheels.yml`](../../.github/workflows/wheels.yml) using
[`cibuildwheel`](https://cibuildwheel.readthedocs.io/) + maturin.

The wheels are `abi3-py38` so a single wheel per platform/arch serves
every Python 3.8+ interpreter.

## Why a separate wheel?

Keeping the Rust crate as a separate companion wheel means:

- **`acgs-lite` stays pure-Python**: installable on any platform, including
  embedded/edge targets, with no Rust toolchain or pre-built wheel required.
- **Performance is opt-in**: users who need the speedup get it by installing
  one extra wheel; users who don't get zero surface area.
- **Decoupled release cadence**: the Rust crate can ship bugfix releases
  without forcing an `acgs-lite` version bump.

## License

Apache-2.0, matching the parent repository.
