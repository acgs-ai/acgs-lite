<!-- Mirrors SECURITY.md at the package root, which supplies the H1. -->
<!-- The path is resolved against `base_path` in mkdocs.yml (the config dir), so -->
<!-- it works in a standalone checkout and inside the ACGS monorepo alike. -->
--8<-- "SECURITY.md"

## Formal verification

The Z3 and Lean 4 layers have their own trust boundary, failure behavior, and policy
language. See [Formal verification](formal-verification.md) for what each layer proves,
what it refuses to prove, and why both block rather than allow when they cannot reach a
verdict.
