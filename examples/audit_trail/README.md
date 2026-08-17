# Example: Tamper-Evident Audit Trail

Every governance decision is recorded in a cryptographically-chained audit log.
Chain integrity is verifiable at any time — no database required.

## What it shows

| Concept | Description |
|---------|-------------|
| `AuditLog` + `AuditEntry` | Record decisions with SHA-256 chain |
| `verify_chain()` | Detect tampering across the full log |
| `query()` | Filter by `agent_id`, `type`, `valid` |
| Export to JSON | Persist the log for compliance reporting |

## Run

`pip install` does **not** ship this directory. From a clone of this repo:

```bash
pip install -e .
python examples/audit_trail/main.py
```

## What this proves

- `AuditLog.record()` appends SHA-256-chained entries in process.
- `verify_chain()` returns `True` on an unmodified log and fails after
  in-memory tampering in the demo.
- Entries can be queried and exported to JSON.

## What this does not claim

- This is an in-process (and optional local-file) demo, not a hosted,
  independently operated audit store.
- A verified chain proves the log was not altered *in this process*. It does
  not prove who issued a decision unless you also use signed receipts
  (`crypto` extra).
- Not certification, not regulator approval, not production durability.

## Key API

```python
from acgs_lite.audit import AuditLog, AuditEntry

log = AuditLog()

# Record a decision
log.record(AuditEntry(
    id="ev-001",
    type="validation",
    agent_id="agent-A",
    action="review_proposal",
    valid=True,
))

# Verify nothing was tampered with
assert log.verify_chain()

# Query by agent
violations = log.query(agent_id="agent-A", valid=False)

# Export for compliance
import json
json.dump([e.to_dict() for e in log.entries], open("audit.json", "w"))
```

## Chain integrity

Each entry's `chain_hash` is `SHA-256(prev_hash | entry_hash)`. Modifying any
historical entry breaks all subsequent chain hashes, which `verify_chain()` detects.

## Next steps

- [`../mock_stub_testing/`](../mock_stub_testing/) — test audit pipelines without external storage
