# Audit Trail

The versioned `sha256-v1` format stores complete SHA-256 digests. When a bounded
log trims old entries, it retains the digest immediately before the retained
window as an anchor, so the remaining segment can still be verified. Repeated
trimming does not regenerate history. Legacy 16-hex-character chains are
verified at their original strength and are not silently rewritten.

This self-contained chain detects alteration inside the retained segment. It
cannot by itself detect deletion or wholesale rewriting of the complete log;
that requires a chain head anchored outside the log's trust domain.

## Class Reference

::: acgs_lite.audit.AuditLog
    options:
      members:
        - record
        - record_durable
        - verify_chain
        - export_json
        - from_json
        - export_dicts
      show_source: true

::: acgs_lite.audit.AuditEntry

## Examples

### Access the audit trail

```python
from acgs_lite import GovernedAgent, Constitution, MACIRole
from acgs_lite.audit import AuditLog

def my_agent(prompt: str) -> str:
    return f"Processed: {prompt}"

agent = GovernedAgent(
    my_agent,
    constitution=Constitution.from_template("general"),
    maci_role=MACIRole.EXECUTOR,
)
result = agent.run("some request", governance_action="execute")

# The trail is automatically populated
trail: AuditLog = agent.audit_log
```

### Verify chain integrity

```python
result = trail.verify_chain()
print(f"Chain valid: {result}")
```

### Export records

```python
trail.export_json("audit_report.json")
```

`export_json()` writes a coherent, versioned snapshot including the retained
predecessor anchor. `AuditLog.from_json(...)` verifies that snapshot before it
is accepted.

### Durability boundary

`record()` and `record_atomic()` are compatibility APIs. They append in memory,
and an attached backend write is best effort; their names do not establish that
bytes reached durable storage.

Use `record_durable()` only with `JSONLAuditBackend` when a side effect requires
an acknowledged backend write, file fsync and directory fsync first. A failed write or
flush restores the in-memory entry and backend checkpoint. If rollback cannot
be confirmed, the log is poisoned and later strict appends fail closed.

The strict JSONL confirmation verifies descriptor/path identity, syncs the file,
and syncs its parent plus the parents of directories created by this backend.
It requires a local OS/filesystem supporting directory fsync; unsupported or
failed confirmation denies the strict append. Compatibility `flush()` retains
its file-only semantics.

Open existing history with `AuditLog.from_backend(backend)`. Before each strict
append, the entire persisted chain is verified and compared with the writer's
retained state. Unrecovered, stale, truncated, corrupted or replaced state is
rejected. This costs O(history) per strict append and is intended for a trusted
local directory with one writer. It is not a hostile-filesystem race defense,
multi-process lock, external anchor, durable execution ledger or platform-wide
crash-recovery protocol. Those guarantees require separate qualification.

### Query records

```python
violations = [r for r in trail.entries if not r.valid]
print(f"{len(violations)} blocked actions in this session")
```
