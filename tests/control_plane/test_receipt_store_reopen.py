"""Reopen behaviour of JSONLReceiptStore for degenerate on-disk states."""

from __future__ import annotations

from pathlib import Path

import pytest

from acgs_lite.control_plane.immutable_core import DEFAULT_IMMUTABLE_CORE
from acgs_lite.control_plane.receipt_ledger import JSONLReceiptStore, ReceiptStoreCorrupted


def _store(tmp_path: Path, name: str) -> JSONLReceiptStore:
    core = DEFAULT_IMMUTABLE_CORE.with_repo_root(str(tmp_path))
    return JSONLReceiptStore(f"audit/{name}", registry=core)


def test_reopen_blank_only_store_is_an_empty_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "r.jsonl"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"\n  \n")

    assert _store(tmp_path, "r.jsonl").read_all() == ()
    assert path.read_bytes() == b"\n  \n"
    assert _store(tmp_path, "r.jsonl").read_all() == ()


def test_reopen_rejects_non_utf8_tail(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "r.jsonl"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"\xff\xfe\n")

    with pytest.raises(ReceiptStoreCorrupted, match="not UTF-8"):
        _store(tmp_path, "r.jsonl")
