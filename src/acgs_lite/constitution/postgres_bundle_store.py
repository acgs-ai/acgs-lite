"""Postgres-backed BundleStore for multi-instance constitution lifecycle state.

SQLite is single-host only: its WAL mode requires shared memory between the
writer and readers, which rules out running multiple acgs-lite server
replicas against one database.  ``PostgresBundleStore`` solves that by
keeping the same ``BundleStore`` protocol while storing rows in a managed
Postgres cluster.

Design mirrors :class:`SQLiteBundleStore`:

- Partial unique index ``WHERE status = 'active'`` enforces one-active-per-
  tenant at the database level.
- All multi-step writes use a single ``BEGIN; ... COMMIT`` block with
  row-level locking so two concurrent ``activate()`` calls cannot both
  observe zero ACTIVE bundles and both succeed.
- Driver exceptions are re-raised as :class:`LifecycleError` so callers
  never see raw psycopg exceptions.
- A ``schema_migrations`` table provides a forward migration path.

This backend is an *optional* extra: install with ``pip install
acgs-lite[postgres]`` which pulls in ``psycopg[binary]>=3.1``.  The module
imports psycopg lazily so ``acgs_lite`` itself stays installable without it.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING, Any

from acgs_lite.constitution.activation import ActivationRecord
from acgs_lite.constitution.bundle import BundleStatus, ConstitutionBundle
from acgs_lite.constitution.bundle_store import CASVersionConflict, _utcnow_dt
from acgs_lite.constitution.lifecycle_service import LifecycleError

if TYPE_CHECKING:
    from psycopg_pool import ConnectionPool

_SCHEMA_VERSION = 1

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS bundles (
    bundle_id   TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    status      TEXT NOT NULL,
    payload     JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bundles_tenant ON bundles(tenant_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active
    ON bundles(tenant_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS activations (
    tenant_id   TEXT PRIMARY KEY,
    bundle_id   TEXT NOT NULL,
    payload     JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_versions (
    tenant_id   TEXT PRIMARY KEY,
    version     INTEGER NOT NULL DEFAULT 0
);
"""


def _utcnow() -> datetime:
    return _utcnow_dt()


def _import_psycopg() -> Any:
    try:
        import psycopg  # noqa: F401

        return psycopg
    except ImportError as exc:  # pragma: no cover - exercised via extra-missing path
        raise ImportError(
            "PostgresBundleStore requires the 'postgres' extra. "
            "Install with: pip install 'acgs-lite[postgres]'"
        ) from exc


class PostgresBundleStore:
    """BundleStore backed by a managed Postgres cluster.

    :param dsn: Postgres connection string (``postgresql://user:pw@host/db``).
        Ignored when ``pool`` is passed.
    :param pool: An existing ``psycopg_pool.ConnectionPool`` instance.
        Preferred for production deployments so pool sizing can be tuned.
    :param min_size: When constructing an internal pool, minimum pool size.
    :param max_size: When constructing an internal pool, maximum pool size.

    Thread safety: Postgres serializes writers at the row level via
    ``SELECT ... FOR UPDATE``.  Cross-instance safety is provided by the
    partial unique index on ``status = 'active'``.

    Supports use as a context manager — ``close()`` is called on ``__exit__``::

        with PostgresBundleStore(dsn="postgresql://...") as store:
            store.save_bundle(bundle)

    **Extension: atomic multi-bundle writes**

    :meth:`save_bundle_transactional` saves multiple bundles (and an optional
    :class:`~acgs_lite.constitution.activation.ActivationRecord`) in a single
    transaction.  Use it when you need atomicity guarantees stronger than the
    individual :meth:`save_bundle` / :meth:`save_activation` pair — for
    example, to make superseding the old active bundle and promoting the new one
    a single commit that can never be observed half-applied by a concurrent
    reader.
    """

    def __init__(
        self,
        dsn: str | None = None,
        *,
        pool: ConnectionPool | None = None,
        min_size: int = 1,
        max_size: int = 10,
        schema_setup: bool = True,
    ) -> None:
        if dsn is None and pool is None:
            raise ValueError("PostgresBundleStore requires either dsn=... or pool=...")
        self._psycopg = _import_psycopg()
        self._owns_pool = pool is None
        if pool is None:
            from psycopg_pool import ConnectionPool

            # type: ignore[assignment]
            self._pool: Any = ConnectionPool(
                conninfo=dsn or "",
                min_size=min_size,
                max_size=max_size,
                open=True,
            )
        else:
            self._pool = pool
        if schema_setup:
            self._ensure_schema()

    # ── lifecycle ────────────────────────────────────────────────────────

    def close(self) -> None:
        """Close the underlying connection pool if this store owns it."""
        if self._owns_pool:
            self._pool.close()

    def __enter__(self) -> PostgresBundleStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ── internal helpers ─────────────────────────────────────────────────

    def _ensure_schema(self) -> None:
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(_SCHEMA_SQL)
                    cur.execute(
                        "SELECT version FROM schema_migrations WHERE version = %s",
                        (_SCHEMA_VERSION,),
                    )
                    if cur.fetchone() is None:
                        cur.execute(
                            "INSERT INTO schema_migrations (version, applied_at) "
                            "VALUES (%s, %s) ON CONFLICT DO NOTHING",
                            (_SCHEMA_VERSION, _utcnow()),
                        )
                conn.commit()
        except self._psycopg.Error as exc:
            raise self._wrap(exc) from exc

    def _wrap(self, exc: Exception) -> LifecycleError:
        return LifecycleError(f"PostgresBundleStore: database error - {exc}")

    # ── BundleStore Protocol ─────────────────────────────────────────────

    def save_bundle(self, bundle: ConstitutionBundle) -> None:
        payload = json.dumps(bundle.model_dump(mode="json"))
        now = _utcnow()
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO bundles (bundle_id, tenant_id, status, payload, updated_at)
                        VALUES (%s, %s, %s, %s::jsonb, %s)
                        ON CONFLICT(bundle_id) DO UPDATE SET
                            tenant_id  = EXCLUDED.tenant_id,
                            status     = EXCLUDED.status,
                            payload    = EXCLUDED.payload,
                            updated_at = EXCLUDED.updated_at
                        """,
                        (bundle.bundle_id, bundle.tenant_id, bundle.status.value, payload, now),
                    )
                conn.commit()
        except self._psycopg.errors.UniqueViolation as exc:
            # Partial unique index on (tenant_id) WHERE status='active' fired.
            raise LifecycleError(
                f"Tenant {bundle.tenant_id!r} already has an ACTIVE bundle"
            ) from exc
        except self._psycopg.Error as exc:
            raise self._wrap(exc) from exc

    def get_bundle(self, bundle_id: str) -> ConstitutionBundle | None:
        try:
            with self._pool.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT payload FROM bundles WHERE bundle_id = %s",
                    (bundle_id,),
                )
                row = cur.fetchone()
        except self._psycopg.Error as exc:
            raise self._wrap(exc) from exc
        if row is None:
            return None
        return ConstitutionBundle.model_validate(_as_dict(row[0]))

    def get_active_bundle(self, tenant_id: str) -> ConstitutionBundle | None:
        try:
            with self._pool.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT payload FROM bundles WHERE tenant_id = %s AND status = 'active'",
                    (tenant_id,),
                )
                row = cur.fetchone()
        except self._psycopg.Error as exc:
            raise self._wrap(exc) from exc
        if row is None:
            return None
        return ConstitutionBundle.model_validate(_as_dict(row[0]))

    def list_bundles(
        self,
        tenant_id: str,
        *,
        status: BundleStatus | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[ConstitutionBundle]:
        order_clause = "ORDER BY (payload->>'version')::int DESC"
        limit_val: int | None = int(limit) if limit is not None else None
        offset_val = int(offset) if offset else 0
        # LIMIT NULL is a PostgreSQL syntax error; use LIMIT ALL when unbounded.
        limit_clause = "LIMIT %s" if limit_val is not None else "LIMIT ALL"
        try:
            with self._pool.connection() as conn, conn.cursor() as cur:
                if status is not None:
                    sql = (
                        f"SELECT payload FROM bundles "
                        f"WHERE tenant_id = %s AND status = %s {order_clause} "
                        f"{limit_clause} OFFSET %s"
                    )
                    params: tuple[Any, ...] = (
                        (tenant_id, status.value, limit_val, offset_val)
                        if limit_val is not None
                        else (tenant_id, status.value, offset_val)
                    )
                else:
                    sql = (
                        f"SELECT payload FROM bundles "
                        f"WHERE tenant_id = %s {order_clause} {limit_clause} OFFSET %s"
                    )
                    params = (
                        (tenant_id, limit_val, offset_val)
                        if limit_val is not None
                        else (tenant_id, offset_val)
                    )
                cur.execute(sql, params)
                rows = cur.fetchall()
        except self._psycopg.Error as exc:
            raise self._wrap(exc) from exc
        return [ConstitutionBundle.model_validate(_as_dict(r[0])) for r in rows]

    def save_activation(self, activation: ActivationRecord) -> None:
        payload = json.dumps(activation.model_dump(mode="json"))
        now = _utcnow()
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO activations (tenant_id, bundle_id, payload, updated_at)
                        VALUES (%s, %s, %s::jsonb, %s)
                        ON CONFLICT(tenant_id) DO UPDATE SET
                            bundle_id  = EXCLUDED.bundle_id,
                            payload    = EXCLUDED.payload,
                            updated_at = EXCLUDED.updated_at
                        """,
                        (activation.tenant_id, activation.bundle_id, payload, now),
                    )
                conn.commit()
        except self._psycopg.Error as exc:
            raise self._wrap(exc) from exc

    def get_activation(self, tenant_id: str) -> ActivationRecord | None:
        try:
            with self._pool.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT payload FROM activations WHERE tenant_id = %s",
                    (tenant_id,),
                )
                row = cur.fetchone()
        except self._psycopg.Error as exc:
            raise self._wrap(exc) from exc
        if row is None:
            return None
        return ActivationRecord.model_validate(_as_dict(row[0]))

    def save_bundle_transactional(
        self,
        bundles: list[ConstitutionBundle],
        activation: ActivationRecord | None = None,
    ) -> None:
        """Save multiple bundles (and optional activation) atomically.

        Uses a single transaction so two concurrent activate() calls can
        never both succeed.  The partial unique index on
        ``(tenant_id) WHERE status='active'`` is the last-resort guard.
        """
        now = _utcnow()
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    for bundle in bundles:
                        payload = json.dumps(bundle.model_dump(mode="json"))
                        cur.execute(
                            """
                            INSERT INTO bundles (
                                bundle_id, tenant_id, status, payload, updated_at
                            )
                            VALUES (%s, %s, %s, %s::jsonb, %s)
                            ON CONFLICT(bundle_id) DO UPDATE SET
                                tenant_id  = EXCLUDED.tenant_id,
                                status     = EXCLUDED.status,
                                payload    = EXCLUDED.payload,
                                updated_at = EXCLUDED.updated_at
                            """,
                            (
                                bundle.bundle_id,
                                bundle.tenant_id,
                                bundle.status.value,
                                payload,
                                now,
                            ),
                        )
                    if activation is not None:
                        apayload = json.dumps(activation.model_dump(mode="json"))
                        cur.execute(
                            """
                            INSERT INTO activations (
                                tenant_id, bundle_id, payload, updated_at
                            )
                            VALUES (%s, %s, %s::jsonb, %s)
                            ON CONFLICT(tenant_id) DO UPDATE SET
                                bundle_id  = EXCLUDED.bundle_id,
                                payload    = EXCLUDED.payload,
                                updated_at = EXCLUDED.updated_at
                            """,
                            (
                                activation.tenant_id,
                                activation.bundle_id,
                                apayload,
                                now,
                            ),
                        )
                conn.commit()
        except self._psycopg.errors.UniqueViolation as exc:
            raise LifecycleError(
                "ACTIVE-bundle uniqueness violated during transactional save"
            ) from exc
        except self._psycopg.Error as exc:
            raise self._wrap(exc) from exc

    def get_tenant_version(self, tenant_id: str) -> int:
        try:
            with self._pool.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT version FROM tenant_versions WHERE tenant_id = %s",
                    (tenant_id,),
                )
                row = cur.fetchone()
        except self._psycopg.Error as exc:
            raise self._wrap(exc) from exc
        return 0 if row is None else int(row[0])

    def cas_tenant_version(self, tenant_id: str, expected: int) -> None:
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    # Advisory lock serializes concurrent callers per tenant,
                    # covering the case where the row does not yet exist
                    # (SELECT FOR UPDATE cannot lock absent rows).
                    # hashtext() is 32-bit so two distinct tenant IDs with the
                    # same hash would serialize unnecessarily — correctness is
                    # preserved (false-positive serialization only), but throughput
                    # degrades. Collision probability is negligible at typical
                    # tenant counts.
                    cur.execute(
                        "SELECT pg_advisory_xact_lock(hashtext(%s)::bigint)",
                        (tenant_id,),
                    )
                    cur.execute(
                        "SELECT version FROM tenant_versions WHERE tenant_id = %s FOR UPDATE",
                        (tenant_id,),
                    )
                    row = cur.fetchone()
                    current = 0 if row is None else int(row[0])
                    if current != expected:
                        conn.rollback()
                        raise CASVersionConflict(
                            f"Tenant {tenant_id!r} version conflict: "
                            f"expected {expected}, current {current}"
                        )
                    cur.execute(
                        """
                        INSERT INTO tenant_versions (tenant_id, version) VALUES (%s, %s)
                        ON CONFLICT(tenant_id) DO UPDATE SET version = EXCLUDED.version
                        """,
                        (tenant_id, current + 1),
                    )
                conn.commit()
        except CASVersionConflict:
            raise
        except self._psycopg.Error as exc:
            raise self._wrap(exc) from exc


def _as_dict(payload: Any) -> dict[str, Any]:
    """Normalize payload column to a dict.

    ``psycopg`` returns ``JSONB`` columns as already-decoded ``dict`` values,
    but some drivers/adapters return the raw JSON string.  Handle both.
    """
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8")
    if isinstance(payload, str):
        decoded = json.loads(payload)
        if isinstance(decoded, dict):
            return decoded
        raise TypeError(f"Unexpected JSONB payload type: {type(decoded).__name__}")
    if isinstance(payload, dict):
        return payload
    raise TypeError(f"Unexpected JSONB payload type: {type(payload).__name__}")


__all__ = ["PostgresBundleStore"]
