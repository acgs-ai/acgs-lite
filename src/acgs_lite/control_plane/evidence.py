"""External evidence: run references that a party other than the agent can check.

Evidence that motivates this module:

* Darwin Goedel Machine: the agent fabricated "tests passed" logs and removed
  hallucination-detection markers; only the lineage archive caught it. So a
  log the agent wrote is never accepted as the sole evidence of success
  (:attr:`EvidenceSource.AGENT_LOG` refs never validate), and every success
  claim must cite an external run (CI system, evaluator service, human
  review) that a verifier re-checks independently of the agent.
* STOP (self-taught optimizer): agents disabled their own sandbox flag, so the
  run registry only accepts registrations from SERVICE/HUMAN principals, its
  JSONL file must live in the agent-unwritable audit area, and every line is
  signed (a raw file write cannot forge a run).
* Evidence is bound to an artifact: success-claim refs must carry
  ``artifact_digest``/``head_sha`` that the verifier matches against its own
  record, so one green run cannot certify a different candidate.

Verifiers never raise from :meth:`ExternalRunVerifier.validate`: any error is
an invalid :class:`RunValidation` (fail closed).
"""

from __future__ import annotations

import importlib
import json
import os
import re
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from acgs_lite._compat import StrEnum
from acgs_lite.control_plane.immutable_core import (
    DEFAULT_IMMUTABLE_CORE,
    CoreCategory,
    ImmutableCoreRegistry,
)
from acgs_lite.control_plane.principal import Principal, PrincipalKind
from acgs_lite.legitimacy.signing import SIGNATURE_ALGORITHM, ReceiptSigner, verify_signature

__all__ = [
    "AGENT_LOG_REASON",
    "DEFAULT_EVIDENCE_POLICY",
    "CompositeRunVerifier",
    "EvidencePolicy",
    "EvidenceSource",
    "ExternalRunRef",
    "ExternalRunVerifier",
    "GitHubActionsRunVerifier",
    "RunRegistrationRejected",
    "RunValidation",
    "TrustedRunRegistry",
    "evaluate_evidence",
    "parse_external_runs",
    "require_audit_store_path",
]

AGENT_LOG_REASON = "agent-written logs are not evidence"
ONLY_AGENT_LOGS_REASON = "only agent-written logs cited as evidence"
CANNOT_ATTEST_REASON = "verifier cannot attest artifact digest"
RUN_RECORD_SIGNING_DOMAIN = b"acgs-control-plane-run-record-v1\x00"

_ID = re.compile(r"[A-Za-z0-9._:/@+-]+")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_GIT_SHA = re.compile(r"[0-9a-fA-F]{40}")
_URL = re.compile(r"[\x21-\x7e]+")
_REPOSITORY = re.compile(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+")
_MAX_ID_LEN = 256
_REF_KEYS = frozenset({"provider", "run_id", "source", "artifact_digest", "url", "head_sha"})


class EvidenceSource(StrEnum):
    """Who produced a run. Only ``AGENT_LOG`` is agent-controlled."""

    CI_SYSTEM = "ci_system"
    EVALUATOR_SERVICE = "evaluator_service"
    HUMAN_REVIEW = "human_review"
    AGENT_LOG = "agent_log"


def _check_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_ID_LEN:
        raise ValueError(f"{label} must be a non-empty string of at most {_MAX_ID_LEN} chars")
    if not _ID.fullmatch(value):
        raise ValueError(f"{label} must be ASCII [A-Za-z0-9._:/@+-]+: {value!r}")
    return value


def _check_digest(value: object, label: str = "artifact_digest") -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{label} must be 'sha256:<64 lowercase hex>'")
    return value


@dataclass(frozen=True)
class ExternalRunRef:
    """A reference to a run that a verifier can look up independently."""

    provider: str
    run_id: str
    source: EvidenceSource
    artifact_digest: str | None = None
    url: str | None = None
    head_sha: str | None = None

    def __post_init__(self) -> None:
        _check_id(self.provider, "provider")
        _check_id(self.run_id, "run_id")
        object.__setattr__(self, "source", EvidenceSource(self.source))
        _check_digest(self.artifact_digest)
        if self.url is not None and (
            not isinstance(self.url, str) or not _URL.fullmatch(self.url) or len(self.url) > 2048
        ):
            raise ValueError("url must be printable ASCII without whitespace")
        if self.head_sha is not None and (
            not isinstance(self.head_sha, str) or not _GIT_SHA.fullmatch(self.head_sha)
        ):
            raise ValueError("head_sha must be a 40-character hex git sha")

    @property
    def label(self) -> str:
        return f"{self.provider}/{self.run_id}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "run_id": self.run_id,
            "source": self.source.value,
            "artifact_digest": self.artifact_digest,
            "url": self.url,
            "head_sha": self.head_sha,
        }

    @classmethod
    def from_dict(cls, data: object) -> ExternalRunRef:
        """Strict: unknown or missing required keys raise ``ValueError``."""
        if not isinstance(data, Mapping):
            raise ValueError("external run ref must be a mapping")
        unknown = set(data) - _REF_KEYS
        if unknown:
            raise ValueError(f"unknown external run ref keys: {sorted(map(str, unknown))}")
        missing = {"provider", "run_id", "source"} - set(data)
        if missing:
            raise ValueError(f"external run ref is missing keys: {sorted(missing)}")
        return cls(
            provider=data["provider"],
            run_id=data["run_id"],
            source=EvidenceSource(data["source"]),
            artifact_digest=data.get("artifact_digest"),
            url=data.get("url"),
            head_sha=data.get("head_sha"),
        )


def parse_external_runs(raw: object) -> tuple[ExternalRunRef, ...]:
    """Parse ``attributes["external_runs"]`` (refs or dicts); ``None`` -> ``()``."""
    if raw is None:
        return ()
    if isinstance(raw, (str, bytes, Mapping)) or not isinstance(raw, (list, tuple)):
        raise ValueError("external_runs must be a list")
    return tuple(
        item if isinstance(item, ExternalRunRef) else ExternalRunRef.from_dict(item) for item in raw
    )


@dataclass(frozen=True)
class RunValidation:
    valid: bool
    reason: str
    verifier_id: str
    workflow: str | None = None
    """Workflow independently observed by the verifier, never caller asserted."""


@runtime_checkable
class ExternalRunVerifier(Protocol):
    """Independently checks that a referenced run exists and succeeded.

    ``attests_artifact_digest`` is True only if :meth:`validate` checks
    ``ref.artifact_digest`` against data the verifier obtains itself (not
    against the ref). Only such verifiers can back a candidate binding.
    """

    verifier_id: str
    attests_artifact_digest: bool

    def validate(self, ref: ExternalRunRef) -> RunValidation: ...


# TODO(control-plane-gap): the accepted sources, the minimum count of
# validated external runs and the success-claim action prefixes are design
# inference (DGM shows agent logs cannot be trusted; it does not say how many
# independent runs suffice or which actions claim success). Configure them
# per deployment.
@dataclass(frozen=True)
class EvidencePolicy:
    """Rules for when external evidence is required and what counts."""

    min_external_runs: int = 1
    accepted_sources: frozenset[EvidenceSource] = field(
        default_factory=lambda: frozenset(
            {
                EvidenceSource.CI_SYSTEM,
                EvidenceSource.EVALUATOR_SERVICE,
                EvidenceSource.HUMAN_REVIEW,
            }
        )
    )
    success_claim_prefixes: tuple[str, ...] = ("promotion.", "eval.", "ci.")

    def __post_init__(self) -> None:
        if isinstance(self.min_external_runs, bool) or not isinstance(self.min_external_runs, int):
            raise ValueError("min_external_runs must be an int")
        if self.min_external_runs < 1:
            raise ValueError("min_external_runs must be >= 1 (agent logs are never enough)")
        sources = frozenset(EvidenceSource(s) for s in self.accepted_sources)
        if EvidenceSource.AGENT_LOG in sources:
            raise ValueError("agent-written logs can never be an accepted evidence source")
        if not sources:
            raise ValueError("accepted_sources must not be empty")
        object.__setattr__(self, "accepted_sources", sources)
        prefixes = tuple(self.success_claim_prefixes)
        if not all(isinstance(p, str) and p for p in prefixes):
            raise ValueError("success_claim_prefixes must be non-empty strings")
        object.__setattr__(self, "success_claim_prefixes", tuple(p.lower() for p in prefixes))

    def is_success_claim(self, action: str) -> bool:
        return action.lower().startswith(self.success_claim_prefixes)


DEFAULT_EVIDENCE_POLICY = EvidencePolicy()


def evaluate_evidence(
    refs: Sequence[ExternalRunRef],
    verifier: ExternalRunVerifier,
    policy: EvidencePolicy = DEFAULT_EVIDENCE_POLICY,
    *,
    required: bool,
    bind_digest: str | None = None,
) -> tuple[str, ...]:
    """Return rejection reasons (empty tuple = evidence acceptable).

    * Every non-agent ref must validate; AGENT_LOG refs are context only.
    * Refs are de-duplicated by ``(provider, run_id)`` before counting, so one
      run cited twice counts once; conflicting duplicates are rejected.
    * When *required* (success claims, promotions) every external ref must be
      bound to an artifact (``artifact_digest`` or ``head_sha``), so one run
      cannot certify an unrelated artifact, and at least
      ``policy.min_external_runs`` distinct accepted runs must validate.
    * With *bind_digest* (a receipt's ``candidate_digest``) every external ref's
      ``artifact_digest`` must equal it.
    """
    reasons: list[str] = []
    validated = 0
    unique: dict[tuple[str, str], ExternalRunRef] = {}
    for ref in refs:
        if ref.source is EvidenceSource.AGENT_LOG:
            continue
        key = (ref.provider, ref.run_id)
        if key in unique and unique[key] != ref:
            reasons.append(f"run {ref.label}: conflicting duplicate references")
        unique.setdefault(key, ref)
    for ref in unique.values():
        if ref.source not in policy.accepted_sources:
            reasons.append(f"run {ref.label}: source {ref.source.value} is not accepted")
            continue
        if required and ref.artifact_digest is None and ref.head_sha is None:
            reasons.append(f"run {ref.label}: not bound to an artifact (artifact_digest/head_sha)")
            continue
        if bind_digest is not None and ref.artifact_digest != bind_digest:
            reasons.append(f"run {ref.label}: artifact_digest does not match the candidate")
            continue
        # A digest only binds if the verifier checks it against its own data;
        # otherwise it is the ref's (i.e. the caller's) unverified assertion.
        if ref.artifact_digest is not None and not _attests_digest(verifier, ref):
            reasons.append(f"run {ref.label}: {CANNOT_ATTEST_REASON}")
            continue
        try:
            result = verifier.validate(ref)
        except Exception as exc:
            reasons.append(f"run {ref.label}: verifier error {type(exc).__name__}")
            continue
        if not isinstance(result, RunValidation) or result.valid is not True:
            why = result.reason if isinstance(result, RunValidation) else "bad verifier result"
            reasons.append(f"run {ref.label} not independently validated: {why}")
            continue
        validated += 1
    if required:
        if not unique:
            reasons.append(ONLY_AGENT_LOGS_REASON if refs else "no external run evidence cited")
        elif validated < policy.min_external_runs:
            reasons.append(
                f"{validated} validated distinct external run(s) < required "
                f"{policy.min_external_runs}"
            )
    return tuple(reasons)


def _attests_digest(verifier: ExternalRunVerifier, ref: ExternalRunRef) -> bool:
    target: object = verifier
    visited: set[int] = set()
    while isinstance(target, CompositeRunVerifier):
        if id(target) in visited:
            return False
        visited.add(id(target))
        target = target.verifier_for(ref)
    return getattr(target, "attests_artifact_digest", False) is True


def require_audit_store_path(
    path: str | Path, registry: ImmutableCoreRegistry = DEFAULT_IMMUTABLE_CORE
) -> Path:
    """Return the on-disk path, or raise if *path* is not core ``AUDIT_LOG``.

    Stores that hold evidence must live where agents cannot write (the PDP's
    INV-CORE-WRITE and repository permissions both cover ``AUDIT_LOG``).
    Relative paths are resolved against ``registry.repo_root`` when set.
    """
    raw = os.fspath(path)
    category = registry.classify(raw)
    if category is not CoreCategory.AUDIT_LOG:
        raise PermissionError(
            f"evidence store path {raw!r} must be immutable-core AUDIT_LOG, got {category}"
        )
    candidate = Path(raw)
    if not candidate.is_absolute() and registry.repo_root is not None:
        candidate = Path(registry.repo_root) / candidate
    return candidate


class RunRegistrationRejected(PermissionError):
    """Raised when a principal may not register a run (or the record is bad)."""


@dataclass(frozen=True)
class _RunRecord:
    provider: str
    run_id: str
    source: EvidenceSource
    conclusion: str
    artifact_digest: str | None
    head_sha: str | None
    registered_by: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "run_id": self.run_id,
            "source": self.source.value,
            "conclusion": self.conclusion,
            "artifact_digest": self.artifact_digest,
            "head_sha": self.head_sha,
            "registered_by": self.registered_by,
        }


_CONCLUSIONS = frozenset({"success", "failure"})
_RECORD_KEYS = frozenset(
    {"provider", "run_id", "source", "conclusion", "artifact_digest", "head_sha", "registered_by"}
)
_LINE_KEYS = frozenset({"record", "key_id", "signature"})


def _record_from_dict(data: object) -> _RunRecord:
    if not isinstance(data, Mapping) or set(data) != _RECORD_KEYS:
        raise ValueError("malformed run registry record")
    ref = ExternalRunRef(
        data["provider"], data["run_id"], EvidenceSource(data["source"]), head_sha=data["head_sha"]
    )
    if data["conclusion"] not in _CONCLUSIONS:
        raise ValueError("malformed run registry conclusion")
    return _RunRecord(
        provider=ref.provider,
        run_id=ref.run_id,
        source=ref.source,
        conclusion=data["conclusion"],
        artifact_digest=_check_digest(data["artifact_digest"]),
        head_sha=ref.head_sha,
        registered_by=_check_id(data["registered_by"], "registered_by"),
    )


def _record_message(record: Mapping[str, Any]) -> bytes:
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return RUN_RECORD_SIGNING_DOMAIN + canonical.encode("utf-8")


class TrustedRunRegistry:
    """Append-only registry of runs, written only by SERVICE/HUMAN principals.

    With ``path`` the registry persists to JSONL (fsync per append) at a path
    that must classify as ``AUDIT_LOG``. Every line is signed by the
    registry's *signer*; on load each line must verify under
    ``trusted_public_keys`` (default: the signer's own key). An unsigned,
    mis-signed or malformed line fails the open (a file write alone cannot
    forge a run). A read-only party passes ``trusted_public_keys`` and no
    signer; it cannot register runs.
    """

    verifier_id = "trusted-run-registry"
    # The registry compares ref.artifact_digest with the digest it recorded.
    attests_artifact_digest = True

    def __init__(
        self,
        *,
        path: str | Path | None = None,
        registry: ImmutableCoreRegistry = DEFAULT_IMMUTABLE_CORE,
        signer: ReceiptSigner | None = None,
        trusted_public_keys: Mapping[str, str] | None = None,
    ) -> None:
        if signer is not None and not isinstance(signer, ReceiptSigner):
            raise TypeError("signer must implement ReceiptSigner")
        self._lock = threading.Lock()
        self._records: dict[tuple[str, str], _RunRecord] = {}
        self._signer = signer
        self._path: Path | None = None
        self._keys: dict[str, str] = {}
        self._end = 0
        self._lines = 0
        if path is None:
            return
        keys = dict(trusted_public_keys or {})
        if signer is not None:
            keys.setdefault(signer.key_id, signer.public_key_hex())
        if not keys:
            raise ValueError("a persisted run registry needs a signer or trusted_public_keys")
        self._keys = keys
        self._path = require_audit_store_path(path, registry)
        self._refresh_persisted()

    def _refresh_persisted(self) -> None:
        """Read newly appended signed records under the writer's file lock.

        Called with the instance lock held (or during construction). A failed
        refresh must prevent validation from trusting a stale cached record.
        """
        if self._path is None:
            return
        try:
            handle = self._path.open("rb")
        except FileNotFoundError:
            if self._end:
                raise ValueError("run registry disappeared since it was opened") from None
            return
        with handle:
            fcntl: Any = importlib.import_module("fcntl")
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
            try:
                size = os.fstat(handle.fileno()).st_size
                if size < self._end:
                    raise ValueError("run registry shrank since it was opened")
                if size > self._end:
                    handle.seek(self._end)
                    self._ingest(handle.read(size - self._end))
                    self._end = size
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _ingest(self, data: bytes) -> None:
        """Verify and add the signed lines in *data* (bytes after ``_end``)."""
        if data and not data.endswith(b"\n"):
            # A complete record without "\n" would be glued to the next line.
            raise ValueError("run registry tail is not newline-terminated")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("run registry is not UTF-8") from exc
        added: dict[tuple[str, str], _RunRecord] = {}
        for line in text.splitlines():
            self._lines += 1
            number = self._lines
            if not line.strip():
                continue
            try:
                envelope = json.loads(line)
                if not isinstance(envelope, Mapping) or set(envelope) != _LINE_KEYS:
                    raise ValueError("unsigned or malformed registry line")
                key = self._keys.get(envelope["key_id"])
                signature = envelope["signature"]
                if not isinstance(key, str) or not isinstance(signature, str):
                    raise ValueError("registry line signed by an untrusted key")
                if not verify_signature(
                    SIGNATURE_ALGORITHM, key, _record_message(envelope["record"]), signature
                ):
                    raise ValueError("bad registry line signature")
                record = _record_from_dict(envelope["record"])
            except (ValueError, TypeError) as exc:
                raise ValueError(f"run registry line {number}: {exc}") from exc
            run_key = (record.provider, record.run_id)
            if run_key in self._records or run_key in added:
                raise ValueError(f"duplicate run in registry: {run_key}")
            added[run_key] = record
        self._records.update(added)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def registered_conclusion(self, ref: ExternalRunRef) -> str | None:
        """The conclusion recorded for *ref*'s run if it is registered with the
        same source and artifact digest, else ``None``."""
        if not isinstance(ref, ExternalRunRef):
            return None
        with self._lock:
            record = self._records.get((ref.provider, ref.run_id))
        if record is None or record.source is not ref.source:
            return None
        if record.artifact_digest != ref.artifact_digest:
            return None
        return record.conclusion

    @property
    def signing_public_key_hex(self) -> str | None:
        return None if self._signer is None else self._signer.public_key_hex()

    def register_run(
        self,
        principal: Principal,
        ref: ExternalRunRef,
        *,
        conclusion: str,
        artifact_digest: str | None = None,
        head_sha: str | None = None,
    ) -> None:
        """Record *ref* with its *conclusion*. Agents are refused outright."""
        if not isinstance(principal, Principal) or principal.kind not in (
            PrincipalKind.SERVICE,
            PrincipalKind.HUMAN,
        ):
            raise RunRegistrationRejected("only SERVICE or HUMAN principals may register runs")
        if not isinstance(ref, ExternalRunRef):
            raise RunRegistrationRejected("ref must be an ExternalRunRef")
        if ref.source is EvidenceSource.AGENT_LOG:
            raise RunRegistrationRejected(AGENT_LOG_REASON)
        if conclusion not in _CONCLUSIONS:
            raise RunRegistrationRejected("conclusion must be 'success' or 'failure'")
        if self._path is not None and self._signer is None:
            raise RunRegistrationRejected("read-only registry (no signer)")
        try:
            digest = _check_digest(artifact_digest)
            sha = ExternalRunRef(ref.provider, ref.run_id, ref.source, head_sha=head_sha).head_sha
        except ValueError as exc:
            raise RunRegistrationRejected(str(exc)) from exc
        if digest is not None and ref.artifact_digest not in (None, digest):
            raise RunRegistrationRejected("artifact_digest disagrees with the ref")
        if sha is not None and ref.head_sha not in (None, sha):
            raise RunRegistrationRejected("head_sha disagrees with the ref")
        record = _RunRecord(
            provider=ref.provider,
            run_id=ref.run_id,
            source=ref.source,
            conclusion=conclusion,
            artifact_digest=digest if digest is not None else ref.artifact_digest,
            head_sha=(sha if sha is not None else ref.head_sha),
            registered_by=principal.id,
        )
        try:
            # What is written must load again (e.g. registered_by length).
            _record_from_dict(record.to_dict())
        except (ValueError, TypeError) as exc:
            raise RunRegistrationRejected(f"run record would not reload: {exc}") from exc
        key = (ref.provider, ref.run_id)
        with self._lock:
            if self._path is None or self._signer is None:
                if key in self._records:
                    raise RunRegistrationRejected(f"run {ref.label} is already registered")
                self._records[key] = record
                return
            self._append_persisted(key, record, ref.label)

    def _append_persisted(self, key: tuple[str, str], record: _RunRecord, label: str) -> None:
        """Read/check/append as one transaction under an exclusive file lock,
        so registries sharing the file cannot both register one run."""
        if self._path is None or self._signer is None:
            raise RunRegistrationRejected("not a persisted, signing registry")
        try:
            fcntl: Any = importlib.import_module("fcntl")
        except ImportError as exc:  # pragma: no cover - non-POSIX only
            raise RunRegistrationRejected("persisted run registry needs POSIX flock") from exc
        payload = record.to_dict()
        line = (
            json.dumps(
                {
                    "record": payload,
                    "key_id": self._signer.key_id,
                    "signature": self._signer.sign(_record_message(payload)),
                },
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                size = os.fstat(handle.fileno()).st_size
                if size < self._end:
                    raise RunRegistrationRejected("run registry shrank since it was opened")
                if size > self._end:
                    handle.seek(self._end)
                    try:
                        self._ingest(handle.read(size - self._end))
                    except ValueError as exc:
                        raise RunRegistrationRejected(f"run registry changed: {exc}") from exc
                    self._end = size
                if key in self._records:
                    raise RunRegistrationRejected(f"run {label} is already registered")
                try:
                    handle.write(line)
                    handle.flush()
                    os.fsync(handle.fileno())
                except BaseException:
                    # Leave no half-registered line behind for a retry to
                    # duplicate (fsync may fail after the bytes are written).
                    handle.truncate(size)
                    raise
                self._end = size + len(line)
                self._records[key] = record
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def validate(self, ref: ExternalRunRef) -> RunValidation:
        def invalid(reason: str) -> RunValidation:
            return RunValidation(False, reason, self.verifier_id)

        if not isinstance(ref, ExternalRunRef):
            return invalid("not an ExternalRunRef")
        if ref.source is EvidenceSource.AGENT_LOG:
            return invalid(AGENT_LOG_REASON)
        with self._lock:
            try:
                self._refresh_persisted()
            except (OSError, ValueError, ImportError) as exc:
                return invalid(f"run registry refresh failed: {exc}")
            record = self._records.get((ref.provider, ref.run_id))
        if record is None:
            return invalid(f"run {ref.label} is not registered")
        if record.source is not ref.source:
            return invalid(f"source mismatch: registered {record.source.value}")
        if record.conclusion != "success":
            return invalid(f"run conclusion is {record.conclusion}")
        # Binding is symmetric: a ref must carry exactly the artifact identity
        # the run was registered for, and cannot claim one it was not.
        if ref.artifact_digest != record.artifact_digest:
            return invalid("artifact digest mismatch")
        if (ref.head_sha or "").lower() != (record.head_sha or "").lower():
            return invalid("head_sha mismatch")
        return RunValidation(True, "registered successful run", self.verifier_id)


def _allowlist(values: Iterable[str], label: str) -> frozenset[str]:
    if isinstance(values, str):
        raise ValueError(f"{label} must be a collection of strings, not a string")
    items = frozenset(values)
    if not items or not all(isinstance(v, str) and v for v in items):
        raise ValueError(f"{label} must be a non-empty collection of non-empty strings")
    return items


class GitHubActionsRunVerifier:
    """Validate GitHub Actions runs via an injected ``fetch(api_path)``.

    Core does no network I/O: the caller supplies ``fetch`` (for example a
    ``gh api`` client) that returns the JSON for
    ``/repos/{owner}/{repo}/actions/runs/{id}``. A run is valid only if it
    is a completed, successful run of an allow-listed workflow file
    (``path``), branch (``head_branch``) and event in ``repository``, for the
    ref's required ``head_sha``. ``head_repository.full_name`` must also match
    the configured repository; fork heads are not trusted origin evidence.
    Any missing field or exception -> invalid.

    The run payload carries no artifact digest, so the verifier attests one
    (``attests_artifact_digest``) only when constructed with
    ``artifact_fetch(api_path) -> iterable of "sha256:<hex>"`` (for example
    from the run's artifact list or build attestations); ``ref.artifact_digest``
    must then be one of them.
    """

    def __init__(
        self,
        fetch: Callable[[str], Mapping[str, Any]],
        *,
        repository: str,
        allowed_workflows: Iterable[str],
        allowed_branches: Iterable[str],
        allowed_events: Iterable[str],
        provider: str = "github-actions",
        artifact_fetch: Callable[[str], Iterable[str]] | None = None,
    ) -> None:
        if not callable(fetch):
            raise TypeError("fetch must be callable")
        if not isinstance(repository, str) or not _REPOSITORY.fullmatch(repository):
            raise ValueError("repository must be 'owner/repo'")
        self._fetch = fetch
        self._repository = repository
        self._workflows = _allowlist(allowed_workflows, "allowed_workflows")
        self._branches = _allowlist(allowed_branches, "allowed_branches")
        self._events = _allowlist(allowed_events, "allowed_events")
        if artifact_fetch is not None and not callable(artifact_fetch):
            raise TypeError("artifact_fetch must be callable")
        self._artifact_fetch = artifact_fetch
        self.attests_artifact_digest = artifact_fetch is not None
        self.provider = _check_id(provider, "provider")
        self.verifier_id = f"github-actions:{repository}"

    def validate(self, ref: ExternalRunRef) -> RunValidation:
        def invalid(reason: str) -> RunValidation:
            return RunValidation(False, reason, self.verifier_id)

        if not isinstance(ref, ExternalRunRef):
            return invalid("not an ExternalRunRef")
        if ref.source is EvidenceSource.AGENT_LOG:
            return invalid(AGENT_LOG_REASON)
        if ref.source is not EvidenceSource.CI_SYSTEM:
            return invalid("GitHub Actions runs must have source ci_system")
        if ref.provider != self.provider:
            return invalid(f"provider {ref.provider!r} is not {self.provider!r}")
        if not ref.run_id.isdigit():
            return invalid("GitHub run ids are numeric")
        if ref.head_sha is None:
            return invalid("head_sha is required for GitHub Actions evidence")
        try:
            payload = self._fetch(f"/repos/{self._repository}/actions/runs/{ref.run_id}")
            if not isinstance(payload, Mapping):
                return invalid("run payload is not a JSON object")
            repo = payload.get("repository")
            head_repo = payload.get("head_repository")
            checks: tuple[tuple[bool, str], ...] = (
                (str(payload.get("id")) == ref.run_id, "run id mismatch"),
                (
                    isinstance(repo, Mapping) and repo.get("full_name") == self._repository,
                    "repository mismatch",
                ),
                (
                    isinstance(head_repo, Mapping)
                    and head_repo.get("full_name") == self._repository,
                    "head repository mismatch or missing origin",
                ),
                (payload.get("status") == "completed", f"run status is {payload.get('status')!r}"),
                (
                    payload.get("conclusion") == "success",
                    f"run conclusion is {payload.get('conclusion')!r}",
                ),
                (
                    isinstance(payload.get("head_sha"), str)
                    and str(payload.get("head_sha")).lower() == ref.head_sha.lower(),
                    "head_sha mismatch",
                ),
                (payload.get("path") in self._workflows, "workflow is not allow-listed"),
                (payload.get("head_branch") in self._branches, "branch is not allow-listed"),
                (payload.get("event") in self._events, "event is not allow-listed"),
            )
            for ok, reason in checks:
                if not ok:
                    return invalid(reason)
            if self._artifact_fetch is not None and ref.artifact_digest is not None:
                path = f"/repos/{self._repository}/actions/runs/{ref.run_id}/artifacts"
                attested = self._artifact_fetch(path)
                if isinstance(attested, (str, bytes)) or ref.artifact_digest not in set(attested):
                    return invalid("artifact digest is not attested by the run")
        except Exception as exc:
            return invalid(f"fetch failed: {type(exc).__name__}")
        return RunValidation(
            True, "completed successful workflow run", self.verifier_id, str(payload["path"])
        )


class CompositeRunVerifier:
    """Route each ref to the verifier registered for its provider."""

    verifier_id = "composite"
    # Resolved per ref by evaluate_evidence via verifier_for(); the composite
    # itself never vouches for a digest.
    attests_artifact_digest = False

    def __init__(self, verifiers: Mapping[str, ExternalRunVerifier]) -> None:
        routed: dict[str, ExternalRunVerifier] = {}
        for provider, verifier in verifiers.items():
            if not isinstance(verifier, ExternalRunVerifier):
                raise TypeError(f"verifier for {provider!r} is not an ExternalRunVerifier")
            routed[_check_id(provider, "provider")] = verifier
        self._verifiers = routed

    @property
    def providers(self) -> Iterable[str]:
        return tuple(sorted(self._verifiers))

    def verifier_for(self, ref: ExternalRunRef) -> ExternalRunVerifier | None:
        return self._verifiers.get(ref.provider)

    def validate(self, ref: ExternalRunRef) -> RunValidation:
        if not isinstance(ref, ExternalRunRef):
            return RunValidation(False, "not an ExternalRunRef", self.verifier_id)
        if ref.source is EvidenceSource.AGENT_LOG:
            return RunValidation(False, AGENT_LOG_REASON, self.verifier_id)
        verifier = self._verifiers.get(ref.provider)
        if verifier is None:
            return RunValidation(False, f"no verifier for provider {ref.provider!r}", "composite")
        try:
            return verifier.validate(ref)
        except Exception as exc:
            return RunValidation(False, f"verifier error {type(exc).__name__}", "composite")
