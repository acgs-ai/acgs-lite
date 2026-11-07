#!/usr/bin/env python3
"""Render .github/CODEOWNERS from the control-plane immutable-core registry.

python scripts/render_codeowners.py            # write .github/CODEOWNERS
python scripts/render_codeowners.py --check    # exit 1 if it is stale
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from acgs_lite.control_plane.iam import render_codeowners  # noqa: E402
from acgs_lite.control_plane.immutable_core import DEFAULT_IMMUTABLE_CORE  # noqa: E402

DEFAULT_OWNER = "@acgs-ai/governance-humans"
DEFAULT_OUTPUT = ROOT / ".github" / "CODEOWNERS"


def render(owners: list[str] | None = None) -> str:
    return render_codeowners(DEFAULT_IMMUTABLE_CORE, owners or [DEFAULT_OWNER])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", action="append", help=f"code owner (default {DEFAULT_OWNER})")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="fail if the file is out of date")
    args = parser.parse_args(argv)
    content = render(args.owner)
    if args.check:
        try:
            current = args.output.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"cannot read {args.output}: {exc}", file=sys.stderr)
            return 1
        if current != content:
            print(f"{args.output} is stale; run scripts/render_codeowners.py", file=sys.stderr)
            return 1
        print(f"{args.output} is up to date")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(content, encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
