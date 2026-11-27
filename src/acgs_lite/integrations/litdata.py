# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Constitutional Hash: 608508a9bd224290

"""LitData integration for ACGS constitutional governance.

Provides ACGSGovernedDataset, a LitData StreamingDataset subclass that injects
constitutional checks into every sample returned during training — enabling
EU AI Act Article 10 training data provenance tracking.

Usage::

    from acgs_lite.integrations.litdata import ACGSGovernedDataset
    from acgs_lite.constitution import Constitution
    from torch.utils.data import DataLoader

    ds = ACGSGovernedDataset(
        "s3://my-bucket/train",
        constitution=Constitution.default(),
        agent_id="trainer",
        strict=False,   # return None for violating samples; filter in collate_fn
    )
    loader = DataLoader(ds, batch_size=32, collate_fn=lambda b: [x for x in b if x is not None])

    # EU AI Act Article 10 report:
    print(ds.provenance_report())

Article 10 compliance:
    The dataset records which samples were evaluated, which constitutional rules
    fired, and how many samples were filtered. Call provenance_report() at the end
    of training to produce an audit-ready summary.
"""

from __future__ import annotations

from typing import Any

import structlog

from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution
from acgs_lite.engine import GovernanceEngine
from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.serialization import serialize_for_governance

logger = structlog.get_logger(__name__)

_CONSTITUTIONAL_HASH = "608508a9bd224290"

try:
    from litdata import StreamingDataset  # type: ignore[import-untyped]

    LITDATA_AVAILABLE = True
    _StreamingDatasetBase = StreamingDataset
except ImportError:
    LITDATA_AVAILABLE = False
    _StreamingDatasetBase = object  # type: ignore[assignment,misc]


class ACGSGovernedDataset(_StreamingDatasetBase):  # type: ignore[misc,valid-type]
    """LitData StreamingDataset with ACGS constitutional governance on every sample.

    Subclass this or instantiate directly. Every call to ``__getitem__`` runs
    the ACGS constitutional engine against the returned sample before passing it
    to the caller. This provides:

    - **EU AI Act Article 10** compliance: every training sample is evaluated
      against the governing constitution and the outcome is recorded.
    - **Fail-closed data governance**: violating samples are blocked (strict=True)
      or returned as ``None`` (strict=False) so callers can filter them out.
    - **Provenance report**: call ``provenance_report()`` at end of training for
      an audit-ready summary of what data was seen, evaluated, and filtered.

    Args:
        input_dir: Path or URL passed to StreamingDataset (local, S3, GCS, etc.).
        constitution: Constitution to validate against. Defaults to Constitution.default().
        agent_id: Identifier for this dataset in audit logs.
        strict: If True (default), raise ConstitutionalViolationError on violation.
            If False, return None and log a warning — caller must filter None values,
            e.g. via a collate_fn.
        **kwargs: Additional keyword arguments forwarded to StreamingDataset.__init__.
    """

    def __init__(
        self,
        input_dir: str,
        *,
        constitution: Constitution | None = None,
        agent_id: str = "governed-dataset",
        strict: bool = True,
        **kwargs: Any,
    ) -> None:
        if not LITDATA_AVAILABLE:
            raise ImportError(
                "litdata is required for ACGSGovernedDataset. Install it with: pip install litdata"
            )
        super().__init__(input_dir, **kwargs)
        self._constitution = constitution or Constitution.default()
        self._agent_id = agent_id
        self._strict = strict
        self._audit_log = AuditLog()
        self._engine = GovernanceEngine(
            self._constitution,
            audit_log=self._audit_log,
            strict=self._strict,
            audit_mode="full",
        )
        # Verify constitutional hash at construction time — fail-closed
        if self._engine._const_hash != _CONSTITUTIONAL_HASH:
            raise RuntimeError(
                f"constitutional hash mismatch: expected {_CONSTITUTIONAL_HASH!r}, "
                f"got {self._engine._const_hash!r} — stale constitution"
            )
        self._samples_evaluated: int = 0
        self._samples_filtered: int = 0
        self._violation_rule_ids: list[str] = []
        logger.info(
            "acgs_governed_dataset_ready",
            agent_id=self._agent_id,
            constitutional_hash=_CONSTITUTIONAL_HASH,
            strict=self._strict,
        )

    # ------------------------------------------------------------------
    # StreamingDataset override
    # ------------------------------------------------------------------

    def __getitem__(self, index: int) -> Any:
        """Return the sample at index, running a constitutional check first.

        In strict mode, raises ConstitutionalViolationError on a bad sample.
        In non-strict mode, returns None for bad samples so callers can filter.
        """
        sample = super().__getitem__(index)
        self._samples_evaluated += 1

        raw = serialize_for_governance(sample)
        if raw is None:
            # Non-serialisable sample (e.g. raw tensor) — pass through with a note
            logger.debug(
                "acgs_governed_dataset_sample_not_serializable",
                agent_id=self._agent_id,
                index=index,
            )
            return sample

        try:
            self._engine.validate(raw, agent_id=self._agent_id)
        except ConstitutionalViolationError as exc:
            self._samples_filtered += 1
            rule_id = exc.rule_id or "unknown"
            self._violation_rule_ids.append(rule_id)
            logger.warning(
                "acgs_governed_dataset_sample_filtered",
                agent_id=self._agent_id,
                index=index,
                rule_id=rule_id,
                violations=getattr(exc, "violations_list", []),
            )
            if self._strict:
                raise
            return None

        return sample

    # ------------------------------------------------------------------
    # Observability / EU AI Act Article 10
    # ------------------------------------------------------------------

    @property
    def samples_evaluated(self) -> int:
        """Total samples evaluated by the governance engine."""
        return self._samples_evaluated

    @property
    def samples_filtered(self) -> int:
        """Samples that failed constitutional checks (filtered or raised)."""
        return self._samples_filtered

    @property
    def audit_entries(self) -> list[Any]:
        """All audit log entries recorded during this dataset lifetime."""
        return self._audit_log.entries

    def provenance_report(self) -> dict[str, Any]:
        """EU AI Act Article 10 provenance summary.

        Returns a dict suitable for logging, storing, or including in model cards::

            {
                "constitutional_hash": "608508a9bd224290",
                "agent_id": "trainer",
                "samples_evaluated": 50000,
                "samples_filtered": 12,
                "filter_rate": 0.00024,
                "violation_rule_ids": {"R001": 9, "R002": 3},
                "governance_stats": {...},
            }
        """
        from collections import Counter

        rule_counts: dict[str, int] = dict(Counter(self._violation_rule_ids))
        filter_rate = (
            self._samples_filtered / self._samples_evaluated if self._samples_evaluated > 0 else 0.0
        )
        return {
            "constitutional_hash": _CONSTITUTIONAL_HASH,
            "agent_id": self._agent_id,
            "samples_evaluated": self._samples_evaluated,
            "samples_filtered": self._samples_filtered,
            "filter_rate": round(filter_rate, 6),
            "violation_rule_ids": rule_counts,
            "governance_stats": self._engine.stats,
        }


__all__ = ["LITDATA_AVAILABLE", "ACGSGovernedDataset"]
