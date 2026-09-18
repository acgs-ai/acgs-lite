"""Streaming response governance for incremental validation.

Validates LLM output streams (SSE, WebSocket) against constitutional
rules using a sliding-window buffer strategy. Chunks are accumulated
and validated when the buffer exceeds a configurable character
threshold, keeping latency low while catching violations as they
emerge.

Constitutional Hash: 608508a9bd224290

Usage::

    from acgs_lite.constitution import Constitution
    from acgs_lite.engine.core import GovernanceEngine
    from acgs_lite.engine.streaming import governed_stream

    engine = GovernanceEngine(Constitution.default())

    # Wrap any sync or async chunk iterator
    for chunk in governed_stream(llm_stream, engine):
        send_to_client(chunk)

    # Or use the validator directly for fine-grained control
    validator = StreamingValidator(engine, window_size=5)
    for chunk in llm_stream:
        result = validator.feed(chunk)
        if result.should_halt:
            break
    final = validator.flush()
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from typing import Any

from acgs_lite.audit import AuditEntry, AuditLog
from acgs_lite.constitution import Severity

from .types import ValidationResult, Violation

log = logging.getLogger(__name__)


# -------------------------------------------------------------------
# Data structures
# -------------------------------------------------------------------


@dataclass(slots=True)
class StreamChunkResult:
    """Result of feeding a single chunk through streaming governance."""

    chunk: str
    passed: bool
    violations: list[Violation] = field(default_factory=list)
    should_halt: bool = False
    buffer_position: int = 0
    window_text: str = ""


@dataclass(slots=True)
class StreamStats:
    """Aggregate metrics for a governed stream."""

    chunks_processed: int = 0
    validations_performed: int = 0
    violations_detected: int = 0
    halted: bool = False
    total_chars: int = 0
    latency_ms: float = 0.0


# -------------------------------------------------------------------
# Streaming validator
# -------------------------------------------------------------------


class StreamingValidator:
    """Validates streaming text using a sliding window.

    Parameters
    ----------
    engine:
        A fully initialised :class:`GovernanceEngine`.
    window_size:
        Maximum number of recent chunks in the sliding window.
    flush_interval_chars:
        Character count threshold that triggers automatic
        validation.
    blocking_severities:
        Set of severity *values* (e.g. ``{"critical"}``) whose
        violations set ``should_halt=True``.
    audit_log:
        Optional :class:`AuditLog` for tamper-evident recording.
    """

    __slots__ = (
        "_engine",
        "_window_size",
        "_flush_interval",
        "_blocking_sevs",
        "_audit_log",
        "_fail_open_on_error",
        "_window",
        "_pending_chars",
        "_position",
        "_stats",
    )

    def __init__(
        self,
        engine: Any,
        *,
        window_size: int = 5,
        flush_interval_chars: int = 500,
        blocking_severities: set[str] | None = None,
        audit_log: AuditLog | None = None,
        fail_open_on_error: bool = False,
    ) -> None:
        self._engine = engine
        self._window_size = max(1, window_size)
        self._flush_interval = max(1, flush_interval_chars)
        if blocking_severities is None:
            import warnings as _warnings

            _warnings.warn(
                "StreamingValidator: blocking_severities is unset — no severity "
                "level will halt the stream. Pass blocking_severities={'critical'} "
                "(or higher) to enable halt-on-violation.",
                UserWarning,
                stacklevel=2,
            )
            self._blocking_sevs: set[str] = set()
        else:
            self._blocking_sevs = blocking_severities
        self._audit_log = audit_log
        self._fail_open_on_error = fail_open_on_error
        self._window: list[str] = []
        self._pending_chars: int = 0
        self._position: int = 0
        self._stats = StreamStats()

    # -- public properties ------------------------------------------

    @property
    def stats(self) -> StreamStats:
        return self._stats

    # -- feed / flush / reset ---------------------------------------

    def feed(self, chunk: str) -> StreamChunkResult:
        """Append *chunk* to the window and validate if needed."""
        self._window.append(chunk)
        self._pending_chars += len(chunk)
        self._position += len(chunk)
        self._stats.chunks_processed += 1
        self._stats.total_chars += len(chunk)

        # Trim window to last N chunks
        if len(self._window) > self._window_size:
            overflow = len(self._window) - self._window_size
            self._window = self._window[overflow:]

        # Validate when we have accumulated enough characters
        if self._pending_chars >= self._flush_interval:
            return self._validate_window(chunk)

        # No validation yet -- pass-through
        return StreamChunkResult(
            chunk=chunk,
            passed=True,
            buffer_position=self._position,
            window_text="",
        )

    async def afeed(self, chunk: str) -> StreamChunkResult:
        """Async version of :meth:`feed`.

        Runs the synchronous :meth:`feed` in the default executor
        to avoid blocking the event loop.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            self.feed,
            chunk,
        )

    def flush(self) -> StreamChunkResult:
        """Validate whatever remains in the buffer."""
        if not self._window:
            return StreamChunkResult(
                chunk="",
                passed=True,
                buffer_position=self._position,
                window_text="",
            )
        return self._validate_window("")

    def reset(self) -> None:
        """Clear all internal state for a fresh stream."""
        self._window.clear()
        self._pending_chars = 0
        self._position = 0
        self._stats = StreamStats()

    # -- internal ---------------------------------------------------

    def _validate_window(self, chunk: str) -> StreamChunkResult:
        window_text = "".join(self._window)
        self._pending_chars = 0
        self._stats.validations_performed += 1

        violations: list[Violation] = []
        should_halt = False
        passed = True

        t0 = time.monotonic()
        try:
            result = self._validate_nonstrict(window_text)
            violations = list(result.violations)
        except Exception as exc:
            elapsed_ms = (time.monotonic() - t0) * 1000
            self._stats.latency_ms += elapsed_ms
            if self._fail_open_on_error:
                log.warning(
                    "streaming validation failed; fail_open_on_error=True, "
                    "treating chunk as passed: %s",
                    exc,
                    exc_info=True,
                )
                return StreamChunkResult(
                    chunk=chunk,
                    passed=True,
                    violations=[],
                    should_halt=False,
                    buffer_position=self._position,
                    window_text=window_text,
                )
            log.error(
                "streaming validation failed; halting stream (fail-closed): %s",
                exc,
                exc_info=True,
            )
            self._stats.halted = True
            return StreamChunkResult(
                chunk=chunk,
                passed=False,
                violations=[],
                should_halt=True,
                buffer_position=self._position,
                window_text=window_text,
            )

        elapsed_ms = (time.monotonic() - t0) * 1000
        self._stats.latency_ms += elapsed_ms

        if violations:
            self._stats.violations_detected += len(violations)
            passed = False
            for v in violations:
                sev_val = v.severity.value if isinstance(v.severity, Severity) else str(v.severity)
                if sev_val in self._blocking_sevs:
                    should_halt = True
                log.warning(
                    "streaming_violation rule=%s severity=%s",
                    v.rule_id,
                    sev_val,
                )

        if should_halt:
            self._stats.halted = True

        self._record_audit(
            window_text,
            violations,
            passed,
            elapsed_ms,
        )

        return StreamChunkResult(
            chunk=chunk,
            passed=passed,
            violations=violations,
            should_halt=should_halt,
            buffer_position=self._position,
            window_text=window_text,
        )

    def _validate_nonstrict(
        self,
        text: str,
    ) -> ValidationResult:
        """Run validation in non-strict mode."""
        with self._engine.non_strict():
            return self._engine.validate(text)

    def _record_audit(
        self,
        window_text: str,
        violations: list[Violation],
        passed: bool,
        latency_ms: float,
    ) -> None:
        if self._audit_log is None:
            return
        entry = AuditEntry(
            id=f"stream-{self._stats.validations_performed}",
            type="streaming_validation",
            action=window_text[:200],
            valid=passed,
            violations=[v.rule_id for v in violations],
            constitutional_hash=self._engine.constitution.hash,
            latency_ms=latency_ms,
        )
        self._audit_log.record(entry)


# -------------------------------------------------------------------
# Stream wrapper
# -------------------------------------------------------------------


_HALT_MESSAGE = "[GOVERNANCE] Stream terminated due to constitutional violation."


class GovernedStreamWrapper:
    """Wraps a sync or async chunk iterator with governance.

    Yields chunks transparently.  When the validator signals
    ``should_halt``, a termination message is yielded and
    iteration stops.

    Parameters
    ----------
    stream:
        Any ``Iterator[str]`` or ``AsyncIterator[str]``.
    validator:
        A configured :class:`StreamingValidator`.
    halt_message:
        Custom message yielded when the stream is halted.
    """

    __slots__ = (
        "_stream",
        "_validator",
        "_halt_message",
        "_stats",
    )

    def __init__(
        self,
        stream: Iterator[str] | AsyncIterator[str],
        validator: StreamingValidator,
        *,
        halt_message: str = _HALT_MESSAGE,
    ) -> None:
        self._stream = stream
        self._validator = validator
        self._halt_message = halt_message
        self._stats = validator.stats

    @property
    def stats(self) -> StreamStats:
        return self._validator.stats

    # -- sync iteration ---------------------------------------------

    def __iter__(self) -> Iterator[str]:
        stream = self._stream
        if not isinstance(stream, Iterator):
            raise TypeError("Wrapped stream is not a sync Iterator")
        for chunk in stream:
            result = self._validator.feed(chunk)
            if result.should_halt:
                yield self._halt_message
                return
            yield chunk
        # Final flush
        final = self._validator.flush()
        if final.should_halt:
            yield self._halt_message

    # -- async iteration --------------------------------------------

    def __aiter__(self) -> AsyncIterator[str]:
        return self._aiter_impl()

    async def _aiter_impl(self) -> AsyncIterator[str]:
        stream = self._stream
        if not isinstance(stream, AsyncIterator):
            raise TypeError("Wrapped stream is not an AsyncIterator")
        async for chunk in stream:
            result = await self._validator.afeed(chunk)
            if result.should_halt:
                yield self._halt_message
                return
            yield chunk
        # Final flush
        final = self._validator.flush()
        if final.should_halt:
            yield self._halt_message


# -------------------------------------------------------------------
# Convenience function
# -------------------------------------------------------------------


def governed_stream(
    stream: Iterator[str] | AsyncIterator[str],
    engine: Any,
    *,
    window_size: int = 5,
    flush_interval_chars: int = 500,
    blocking_severities: set[str] | None = None,
    audit_log: AuditLog | None = None,
    halt_message: str = _HALT_MESSAGE,
) -> GovernedStreamWrapper:
    """Wrap any iterable of text chunks with governance.

    Returns a :class:`GovernedStreamWrapper` that validates each
    chunk against *engine* and halts on blocking-severity violations.

    Parameters
    ----------
    stream:
        Sync ``Iterator[str]`` or ``AsyncIterator[str]``.
    engine:
        A :class:`GovernanceEngine` instance.
    window_size:
        Number of recent chunks in the sliding window (default 5).
    flush_interval_chars:
        Character threshold before validation fires (default 500).
    blocking_severities:
        Severity values that halt the stream.
    audit_log:
        Optional audit log for recording stream validations.
    halt_message:
        Message yielded when the stream is halted.
    """
    validator = StreamingValidator(
        engine,
        window_size=window_size,
        flush_interval_chars=flush_interval_chars,
        blocking_severities=blocking_severities,
        audit_log=audit_log,
    )
    return GovernedStreamWrapper(
        stream,
        validator,
        halt_message=halt_message,
    )
