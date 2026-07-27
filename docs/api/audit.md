# Audit Trail

The log is tamper-evident: altering a recorded entry breaks the hash chain and is detected by verify_chain(). This does not protect against deletion or wholesale rewrite of the log unless the chain head is anchored externally.

## Class Reference

::: acgs_lite.audit.AuditLog
    options:
      members:
        - record
        - verify_chain
        - export_json
        - export_dicts
      show_source: true

::: acgs_lite.audit.AuditEntry

## Examples

### Access the audit trail

```python
from acgs_lite import GovernedAgent, Constitution, MACIRole
from acgs_lite.audit import AuditLog

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

### Query records

```python
violations = [r for r in trail.entries if not r.valid]
print(f"{len(violations)} blocked actions in this session")
```
