#!/usr/bin/env python3
"""Create and verify hash-bound local or publishable release candidates."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import subprocess
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "acgs-lite-release-candidate-v1"
PASS_STATUS = "PASS_WITHIN_STATED_SCOPE"
EXCLUDED_PARTS = {
    ".git",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mode(path: Path) -> str:
    return "100755" if path.stat().st_mode & stat.S_IXUSR else "100644"


def _eligible(path: Path) -> bool:
    return path.is_file() and not any(
        part in EXCLUDED_PARTS or part.startswith(".venv") for part in path.parts
    )


def discover_source_paths(root: Path, output: Path | None = None) -> list[Path]:
    """Return tracked and untracked candidate inputs, excluding generated outputs."""
    try:
        completed = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=root,
            check=True,
            capture_output=True,
        )
        candidates = [Path(raw.decode()) for raw in completed.stdout.split(b"\0") if raw]
    except (OSError, subprocess.CalledProcessError):
        candidates = [path.relative_to(root) for path in root.rglob("*")]
    output_resolved = output.resolve() if output else None
    return sorted(
        path
        for path in candidates
        if _eligible(root / path)
        and (output_resolved is None or (root / path).resolve() != output_resolved)
    )


def create_manifest(
    *,
    source_root: Path,
    source_paths: Iterable[Path],
    artifacts: Iterable[Path],
    provenance: str,
    source_ref: str,
    source_sha: str,
    qualification: dict[str, Any],
    evidence: Iterable[Path] = (),
) -> dict[str, Any]:
    if provenance not in {"git", "local-uncommitted"}:
        raise ValueError("unsupported source provenance")
    source_entries = []
    for relative in sorted(source_paths):
        path = source_root / relative
        if not _eligible(path):
            continue
        source_entries.append(
            {"path": relative.as_posix(), "mode": _mode(path), "sha256": sha256_file(path)}
        )
    artifact_entries = []
    artifact_names: set[str] = set()
    for path in sorted(artifacts, key=lambda item: item.name):
        if path.is_symlink() or not path.is_file():
            raise ValueError("artifacts must be regular files")
        if path.name in artifact_names:
            raise ValueError(f"duplicate artifact name: {path.name}")
        artifact_names.add(path.name)
        artifact_entries.append(
            {"name": path.name, "size": path.stat().st_size, "sha256": sha256_file(path)}
        )
    if not artifact_entries:
        raise ValueError("candidate must contain artifacts")
    evidence_entries = []
    evidence_names: set[str] = set()
    for path in sorted(evidence, key=lambda item: item.name):
        if path.is_symlink() or not path.is_file():
            raise ValueError("evidence must be regular files")
        if path.name in evidence_names:
            raise ValueError(f"duplicate evidence name: {path.name}")
        evidence_names.add(path.name)
        evidence_entries.append(
            {"name": path.name, "size": path.stat().st_size, "sha256": sha256_file(path)}
        )
    return {
        "schema": SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": {"provenance": provenance, "ref": source_ref, "sha": source_sha},
        "source_files": source_entries,
        "artifacts": artifact_entries,
        "evidence": evidence_entries,
        "qualification": qualification,
    }


def verify_manifest(
    manifest: dict[str, Any],
    artifact_dir: Path,
    *,
    for_publish: bool = False,
    source_root: Path | None = None,
) -> None:
    if manifest.get("schema") != SCHEMA:
        raise ValueError("unsupported candidate schema")
    source = manifest.get("source", {})
    if for_publish and source.get("provenance") != "git":
        raise ValueError("local-uncommitted provenance cannot be published")
    qualification = manifest.get("qualification", {})
    if qualification.get("status") != PASS_STATUS:
        raise ValueError("qualification did not pass")
    if qualification.get("source_sha") not in {None, source.get("sha")}:
        raise ValueError("qualification source does not match candidate source")
    if for_publish:
        required_evidence = {
            "tests.xml",
            "coverage.json",
            "wheel-qualification.json",
            "qualification.json",
        }
        evidence_names = {item.get("name") for item in manifest.get("evidence", [])}
        if not required_evidence.issubset(evidence_names):
            raise ValueError("candidate is missing required qualification evidence")
        for key in ("wheel_status", "coverage_status", "source_suite_status"):
            if qualification.get(key) != PASS_STATUS:
                raise ValueError(f"qualification {key} did not pass")
    for expected in manifest.get("artifacts", []):
        path = artifact_dir / expected["name"]
        if (
            not path.is_file()
            or path.stat().st_size != expected["size"]
            or sha256_file(path) != expected["sha256"]
        ):
            raise ValueError(f"artifact digest mismatch: {expected['name']}")
    for expected in manifest.get("evidence", []):
        path = artifact_dir / expected["name"]
        if (
            not path.is_file()
            or path.stat().st_size != expected["size"]
            or sha256_file(path) != expected["sha256"]
        ):
            raise ValueError(f"evidence digest mismatch: {expected['name']}")
    if source_root is not None:
        expected_paths = {item["path"] for item in manifest.get("source_files", [])}
        actual_paths = {item.as_posix() for item in discover_source_paths(source_root)}
        if expected_paths != actual_paths:
            raise ValueError("source manifest file set mismatch")
        for expected in manifest.get("source_files", []):
            path = source_root / expected["path"]
            if (
                not path.is_file()
                or _mode(path) != expected["mode"]
                or sha256_file(path) != expected["sha256"]
            ):
                raise ValueError(f"source manifest mismatch: {expected['path']}")
        if source.get("provenance") == "git":
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=source_root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            if head != source.get("sha"):
                raise ValueError("source SHA does not match checkout HEAD")


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def verify_publish_metadata(
    manifest: dict[str, Any],
    expected: dict[str, str],
    *,
    now: str | None = None,
    max_age_hours: int = 24,
) -> None:
    source = manifest.get("source", {})
    if source.get("provenance") != "git":
        raise ValueError("local-uncommitted provenance cannot be published")
    qualification = manifest.get("qualification", {})
    if qualification.get("status") != PASS_STATUS:
        raise ValueError("qualification did not pass")
    actual = dict(qualification)
    actual["source_ref"] = source.get("ref")
    for field, value in expected.items():
        if str(actual.get(field)) != str(value):
            raise ValueError(f"publish metadata {field} mismatch")
    if (
        qualification.get("conclusion") != "success"
        or qualification.get("event_name") != "workflow_dispatch"
    ):
        raise ValueError("candidate run was not a successful manual qualification")


def verify_run_metadata(
    manifest: dict[str, Any],
    run: dict[str, Any],
    *,
    now: str | None = None,
    max_age_hours: int = 24,
) -> None:
    qualification = manifest["qualification"]
    source = manifest["source"]
    expected = {
        "id": int(qualification["run_id"]),
        "run_attempt": int(qualification["run_attempt"]),
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "path": qualification["workflow_path"],
        "head_sha": source["sha"],
    }
    for field, value in expected.items():
        if run.get(field) != value:
            raise ValueError(f"fetched run {field} mismatch")
    repository = qualification["repository"]
    if run.get("repository", {}).get("full_name") != repository:
        raise ValueError("fetched run repository mismatch")
    if run.get("head_repository", {}).get("full_name") != repository:
        raise ValueError("fetched run head repository mismatch")
    current = _parse_utc(now) if now else datetime.now(timezone.utc)
    created = _parse_utc(run["created_at"])
    if current < created or (current - created).total_seconds() > max_age_hours * 3600:
        raise ValueError("fetched run is stale or from the future")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--source-root", type=Path, default=Path("."))
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--artifact", type=Path, action="append", required=True)
    create.add_argument("--evidence", type=Path, action="append", default=[])
    create.add_argument("--qualification", type=Path, required=True)
    create.add_argument("--provenance", choices=("git", "local-uncommitted"), required=True)
    create.add_argument("--source-ref", required=True)
    create.add_argument("--source-sha", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--artifact-dir", type=Path, required=True)
    verify.add_argument("--source-root", type=Path)
    verify.add_argument("--for-publish", action="store_true")
    publish = subparsers.add_parser("verify-publish")
    publish.add_argument("--manifest", type=Path, required=True)
    publish.add_argument("--artifact-dir", type=Path, required=True)
    publish.add_argument("--source-root", type=Path, required=True)
    publish.add_argument("--repository", required=True)
    publish.add_argument("--workflow-path", required=True)
    publish.add_argument("--run-id", required=True)
    publish.add_argument("--source-ref", required=True)
    publish.add_argument("--run-json", type=Path, required=True)
    publish.add_argument("--max-age-hours", type=int, default=24)
    args = parser.parse_args(argv)
    if args.command == "create":
        source_root = args.source_root.resolve()
        if args.provenance == "git":
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=source_root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            resolved = subprocess.run(
                ["git", "rev-parse", f"{args.source_ref}^{{commit}}"],
                cwd=source_root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            dirty = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=source_root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            if dirty or head != args.source_sha or resolved != head:
                raise ValueError(
                    "git candidate requires a clean checkout matching source SHA and ref"
                )
        qualification = json.loads(args.qualification.read_text(encoding="utf-8"))
        payload = create_manifest(
            source_root=source_root,
            source_paths=discover_source_paths(source_root, args.output),
            artifacts=args.artifact,
            provenance=args.provenance,
            source_ref=args.source_ref,
            source_sha=args.source_sha,
            qualification=qualification,
            evidence=args.evidence,
        )
        _write_json(args.output, payload)
    elif args.command == "verify":
        payload = json.loads(args.manifest.read_text(encoding="utf-8"))
        verify_manifest(
            payload,
            args.artifact_dir,
            for_publish=args.for_publish,
            source_root=args.source_root,
        )
    else:
        payload = json.loads(args.manifest.read_text(encoding="utf-8"))
        verify_manifest(
            payload,
            args.artifact_dir,
            for_publish=True,
            source_root=args.source_root,
        )
        verify_publish_metadata(
            payload,
            {
                "repository": args.repository,
                "workflow_path": args.workflow_path,
                "event_name": "workflow_dispatch",
                "head_repository": args.repository,
                "run_id": args.run_id,
                "source_ref": args.source_ref,
            },
            max_age_hours=args.max_age_hours,
        )
        verify_run_metadata(
            payload,
            json.loads(args.run_json.read_text(encoding="utf-8")),
            max_age_hours=args.max_age_hours,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
