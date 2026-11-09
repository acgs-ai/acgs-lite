#!/usr/bin/env python3
"""Extend the trusted CI snapshot from the canonical control-plane registry.

Run with PYTHONPATH=src once the control-plane package is present. Old entries
remain protected until a separately reviewed policy change removes them.
The bootstrap snapshot was exported from the reviewed phase-1/phase-6 union.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def registry_paths() -> list[dict[str, object]]:
    from acgs_lite.control_plane.immutable_core import (
        DEFAULT_IMMUTABLE_CORE,
        compile_glob,
        module_shadow_patterns,
    )

    patterns = {value for values in DEFAULT_IMMUTABLE_CORE.patterns().values() for value in values}
    patterns.update(
        {shadow for value in tuple(patterns) for shadow in module_shadow_patterns(value)}
    )
    patterns.update(DEFAULT_IMMUTABLE_CORE.import_shadow_patterns())
    patterns.update({"**/sitecustomize*", "**/usercustomize*", "**/*.pth", "**/conftest.py"})
    rows: list[dict[str, object]] = []
    for pattern in sorted(patterns):
        compiled = compile_glob(pattern)
        rows.append({"pattern": pattern, "regex": compiled.pattern, "flags": compiled.flags})
    packages = DEFAULT_IMMUTABLE_CORE._src_packages
    if packages:
        alternatives = "|".join(re.escape(value) for value in sorted(packages))
        rows.append(
            {
                "pattern": "@implicit-src-shadow:" + ",".join(sorted(packages)),
                "regex": f"src/(?!(?:{alternatives})(?:/|$)).*",
                "flags": int(re.IGNORECASE | re.DOTALL | re.UNICODE),
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=Path(".github/immutable-core-policy.json"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text())
    existing = {row["pattern"]: row for row in policy["protected_paths"]}
    expected = registry_paths()
    missing = [str(row["pattern"]) for row in expected if existing.get(row["pattern"]) != row]
    if args.check:
        if missing:
            print("trusted policy snapshot is stale: " + ", ".join(missing))
            return 1
        print("trusted policy snapshot covers the canonical registry")
        return 0
    existing.update({str(row["pattern"]): row for row in expected})
    policy["protected_paths"] = [existing[key] for key in sorted(existing)]
    args.policy.write_text(json.dumps(policy, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
