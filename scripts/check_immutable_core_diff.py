#!/usr/bin/env python3
"""Legacy local authorship lint for changes to the immutable core.

CI authorization is enforced by ``scripts/trusted_core_guard.py`` using trusted
policy and commit-bound human authorization; this heuristic is not CI authority.

    check_immutable_core_diff.py --base SHA --head SHA --author LOGIN \
        [--head-ref BRANCH] [--commit-messages-file FILE] [--repo DIR]
    check_immutable_core_diff.py --files a.py evaluator/x.py --author LOGIN

A change is agent-authored when the author login, the head branch or any
commit-message trailer matches an agent pattern. Exit codes: 0 = allowed,
1 = blocked *or* unable to decide (git error, unreadable input: fail closed),
2 = usage error.

For local comparisons, run this from a checkout of the *base* ref so a candidate
cannot edit the lint rules that judge it.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from acgs_lite.control_plane.immutable_core import (  # noqa: E402
    DEFAULT_IMMUTABLE_CORE,
    ImmutableCoreError,
    ImmutableCoreRegistry,
)

# TODO(control-plane-gap): agent detection is heuristic (login suffix, branch
# prefix, commit trailers) and spoofable by anyone who controls those strings;
# real attribution needs signed agent identities (later phase). All patterns
# are overridable with --agent-patterns KIND:REGEX.
DEFAULT_AGENT_PATTERNS: dict[str, tuple[str, ...]] = {
    "author": (r"\[bot\]$",),
    "branch": (r"^agent/",),
    "trailer": (
        r"(?im)^co-authored-by:\s*claude\b",
        r"(?im)^co-authored-by:[^\n]*\bagent\b",
        r"(?im)^co-authored-by:[^\n]*\[bot\]",
        r"(?im)^(?:agent|generated-by|ai-agent):\s*\S",
    ),
}


class GuardError(Exception):
    """Inputs could not be established; the guard fails closed."""


def parse_agent_patterns(values: Sequence[str] | None) -> dict[str, tuple[str, ...]]:
    if not values:
        return dict(DEFAULT_AGENT_PATTERNS)
    patterns: dict[str, list[str]] = {"author": [], "branch": [], "trailer": []}
    for value in values:
        kind, sep, regex = value.partition(":")
        if not sep or kind not in patterns or not regex:
            raise GuardError(f"--agent-patterns must be author|branch|trailer:REGEX, got {value!r}")
        try:
            re.compile(regex)
        except re.error as exc:
            raise GuardError(f"invalid regex {regex!r}: {exc}") from exc
        patterns[kind].append(regex)
    return {kind: tuple(items) for kind, items in patterns.items()}


def agent_reasons(
    author: str,
    head_ref: str,
    commit_messages: str,
    patterns: dict[str, tuple[str, ...]],
) -> list[str]:
    reasons: list[str] = []
    for regex in patterns.get("author", ()):
        if re.search(regex, author):
            reasons.append(f"author {author!r} matches {regex!r}")
    for regex in patterns.get("branch", ()):
        if head_ref and re.search(regex, head_ref):
            reasons.append(f"head ref {head_ref!r} matches {regex!r}")
    for regex in patterns.get("trailer", ()):
        if commit_messages and re.search(regex, commit_messages):
            reasons.append(f"commit trailer matches {regex!r}")
    return reasons


def changed_files(repo: Path, base: str, head: str) -> list[str]:
    # --no-renames lists both the old and the new path of a rename, so moving
    # a core file away is caught too.
    cmd = ["git", "-C", str(repo), "diff", "--name-only", "--no-renames", "-z", f"{base}...{head}"]
    try:
        completed = subprocess.run(cmd, capture_output=True, check=False, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        raise GuardError(f"git diff failed: {exc}") from exc
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", "replace").strip()
        raise GuardError(f"git diff exited {completed.returncode}: {stderr}")
    return [name for name in completed.stdout.decode("utf-8", "replace").split("\0") if name]


def core_hits(files: Sequence[str], registry: ImmutableCoreRegistry) -> list[tuple[str, str]]:
    hits = []
    for name in files:
        category = registry.classify(name)
        if category is not None:
            hits.append((name, category.value))
    return hits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Block agent-authored immutable-core changes.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--files", nargs="+", help="explicit changed paths")
    source.add_argument("--base", help="base commit (requires --head)")
    parser.add_argument("--head", help="head commit")
    parser.add_argument("--repo", type=Path, default=Path("."), help="git work tree")
    parser.add_argument("--author", required=True, help="PR author login")
    parser.add_argument("--head-ref", default="", help="PR head branch name")
    parser.add_argument("--commit-messages-file", type=Path, help="file with commit messages")
    parser.add_argument("--manifest", type=Path, help="immutable-core YAML (default: built-in)")
    parser.add_argument(
        "--agent-patterns",
        action="append",
        help="KIND:REGEX with KIND in author|branch|trailer; replaces the defaults",
    )
    args = parser.parse_args(argv)
    if args.base is not None and not args.head:
        parser.error("--base requires --head")

    try:
        patterns = parse_agent_patterns(args.agent_patterns)
        registry = (
            ImmutableCoreRegistry.from_yaml(args.manifest)
            if args.manifest is not None
            else DEFAULT_IMMUTABLE_CORE
        )
        messages = ""
        if args.commit_messages_file is not None:
            messages = args.commit_messages_file.read_text(encoding="utf-8")
        files = args.files if args.files else changed_files(args.repo, args.base, args.head)
    except (GuardError, ImmutableCoreError, OSError, UnicodeDecodeError) as exc:
        print(f"immutable-core guard: cannot decide, failing closed: {exc}", file=sys.stderr)
        return 1

    reasons = agent_reasons(args.author, args.head_ref, messages, patterns)
    hits = core_hits(files, registry)
    if reasons and hits:
        print("immutable-core guard: BLOCKED agent-authored change to the immutable core")
        for reason in reasons:
            print(f"  agent signal: {reason}")
        for name, category in hits:
            print(f"  core path: {name} ({category})")
        return 1
    if hits:
        print(f"immutable-core guard: {len(hits)} core path(s) changed by a human; review required")
    else:
        print("immutable-core guard: no immutable-core paths changed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
