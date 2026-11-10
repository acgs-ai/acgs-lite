# Upgrading to v4.0.0

4.0.0 is a breaking release. It changes how `GovernedAgent` builds its engine
context, which values governed functions accept, and what the production profile
of `GovernedCallable` requires. This page covers upgrading from 3.0.x. The full
list of changes is in the [changelog](changelog.md).

## Do these first

1. If you call `GovernedAgent.run()` / `arun()` with keyword arguments that your
   rules read (`env=`, `environment=`, `domain=`, `human_approval=`, a timestamp,
   or any key used in a rule `condition` or a custom validator), move them into
   `governance_context=` (see below). **This one fails silently**: the old call
   raises no error, but a rule conditioned on that key stops matching, so the
   action it used to deny is allowed.
2. Make every value passed to or returned from a governed function or agent
   JSON-native (see below).
3. If you use `GovernedCallable(authorization_profile="production")`, provide a
   persistent Ed25519 signer and pin its key (see below), and install
   `acgs-lite[crypto]` wherever it runs.
4. Stop relying on `strict=False` to let a violating call run. Catch
   `ConstitutionalViolationError` instead.

Then install the new version and check it:

```bash
python -m pip install "acgs-lite>=4.0.0"
python -c "import acgs_lite; print(acgs_lite.__version__)"
```

## `GovernedAgent`: engine context comes from `governance_context`

`run()` and `arun()` keyword arguments no longer reach the engine as its
evaluation context. The context is built only from the constructor argument
`governance_context=` (a mapping, copied at construction and never merged with
per-call keyword arguments) plus the call's resolved `governance_action`.
Keyword arguments are still evaluated in full as payload content.

Before (3.0.x):

```python
agent = GovernedAgent(my_agent, constitution=constitution, maci_role=MACIRole.EXECUTOR)
agent.run("deploy the service", governance_action="execute", env="production")
```

After (4.0.0):

```python
agent = GovernedAgent(
    my_agent,
    constitution=constitution,
    maci_role=MACIRole.EXECUTOR,
    governance_context={"env": "production"},  # from deployment configuration
)
agent.run("deploy the service", governance_action="execute")
```

Things to check while migrating:

- **Conditional rules.** A rule whose condition key is missing from
  `governance_context` is inactive, unless its condition uses `"missing": "match"`,
  for example `{"env": {"op": "in", "value": ["production"], "missing": "match"}}`.
  Review every conditional rule.
- **Output is governed with the same context.** A rule conditioned on a context
  value, or bounded by its clock, now also applies to what the agent returns. The
  output check adds `"source": "agent_output"` unless `governance_context` sets
  `source` itself.
- **One agent per trusted context.** Build a separate `GovernedAgent` for each
  distinct context instead of passing different values per call.
- **CDP records.** The `human_approval` and `domain` inputs of the CDP record are
  read from `governance_context`, not from call keyword arguments.
- **`action_detail` / `action_description`** passed as `run()` keyword arguments
  are no longer matched as context values; their text is still matched as payload.

### Pinning `governance_action`

An operator can pin the action label in the constructor:

```python
agent = GovernedAgent(
    my_agent,
    constitution=constitution,
    maci_role=MACIRole.EXECUTOR,
    governance_context={"governance_action": "execute"},
)

agent.run("summarise this document")                              # checked as "execute"
agent.run("summarise this document", governance_action="execute")  # equal: allowed
agent.run("summarise this document", governance_action="read")     # GovernanceError
```

When the label is pinned:

- the pinned label is what MACI checks, what rule conditions see and what the CDP
  record carries;
- a per-call `governance_action` that differs raises `GovernanceError`
  (`rule_id="MACI-ACTION"`) before the agent runs, and an equal one is allowed;
- the pinned label alone satisfies the MACI requirement for a label;
- a pinned value that is not a non-empty string raises `TypeError` at
  construction.

If you do not pin it, the per-call `governance_action` is asserted by the caller
of `run()`. Never derive it from model output, tool arguments or request data.

## `GovernedAgent`: fail-closed payloads and `strict=False`

`run()` and `arun()` now enforce the same payload contract as `GovernedCallable`
on the input string, the keyword arguments and the agent's output:

- Content over 10,000 characters denies with `GOVERNANCE-PAYLOAD-OVERSIZE`.
- Non-JSON values (framework callbacks, clients, message or response objects)
  deny with `GOVERNANCE-PAYLOAD-UNEVALUABLE`. Both raise `GovernancePayloadError`
  (`acgs_lite.serialization`).
- `strict=False` no longer lets a blocking input, keyword or output violation
  through. Warning-level violations still pass.

What to change:

- Catch `ConstitutionalViolationError` (`acgs_lite.errors`) where the old code read
  the result of a violating `strict=False` run.
- Return a JSON-native value from the wrapped agent, for example
  `message.content` or `response.model_dump(mode="json")`, or pass
  `validate_output=False` to skip output enforcement on purpose (this also
  disables structured-output injection).
- Pass handles such as callbacks and clients through a closure or the agent's
  constructor, not as `run()` keyword arguments.
- Keep each input, keyword-argument mapping and output within 10,000 characters.

## Governed values must be JSON-native

`GovernedCallable` and `GovernedAgent` accept only these exact types (matched with
`type(v) is T`, so subclasses are refused): `dict` with exact `str` keys, `list`,
`tuple`, `str`, `int`, `bool`, finite `float`, `None`, and `bytes`/`bytearray` that
decode as strict UTF-8 with no NUL. Text and keys that contain C0 control
characters other than tab, newline and carriage return are also denied.

Everything else denies with `GOVERNANCE-PAYLOAD-UNEVALUABLE`, on input and output,
at any depth, in every profile. That includes `Enum` members, dataclasses,
pydantic models, `datetime`/`date`/`time`, `UUID`, paths, `Decimal`, sets,
`NamedTuple`, non-`dict` mappings, non-`str` dict keys, NaN and infinities.
A return value that is not JSON-native denies after the call ran: the attempt is
recorded `PARTIAL` and the caller does not receive the result.

Convert at the call site, because the governed function receives exactly the
value that was evaluated:

| Value | Convert with |
| --- | --- |
| pydantic model | `model.model_dump(mode="json")` |
| dataclass | `dataclasses.asdict(...)`, then convert its fields |
| `datetime` / `date` / `time` | `value.isoformat()` |
| `UUID`, path, `Decimal` | `str(value)` |
| `Enum` member | `member.value` |
| set | `sorted(...)` |
| dict with non-`str` keys | use `str` keys |

New limits that deny: more than 256 distinct text leaves and keys in one value,
and more than 1024 payloads in one projection. Nesting deeper than 32 levels and
reference cycles still deny.

## `GovernedCallable` production profile

`GovernedCallable(authorization_profile="production")` now requires:

- `receipt_signer=`: a non-ephemeral Ed25519 signer. Keys from
  `Ed25519ReceiptSigner.generate()` are refused. Load a persistent key with
  `Ed25519ReceiptSigner.from_private_bytes(...)` or use a KMS/HSM-backed
  `ReceiptSigner`.
- `trusted_execution_keys=`: `key_id -> public key hex`, from deployment
  configuration, pinning the signer's key with execution scope.
  `trusted_issuer_keys` no longer authorizes execution, and moving a key from it
  does not grant execution scope by itself.
- the `crypto` extra: `python -m pip install "acgs-lite[crypto]>=4.0.0"`.

A missing, ephemeral, unpinned or non-Ed25519 signer raises
`LegitimacyInvariantError` at construction. The production profile also rejects
`strict=False`. `receipt_signer`, `trusted_execution_keys` and `grant_ttl_seconds`
are refused outside the production profile; the compatibility profile is unchanged.

```python
from acgs_lite import AuthorizationProfile, GovernedCallable
from acgs_lite.legitimacy import Ed25519ReceiptSigner

signer = Ed25519ReceiptSigner.from_private_bytes(private_key_bytes)  # loaded from your secret store
governed = GovernedCallable(
    constitution,
    authorization_profile=AuthorizationProfile.PRODUCTION,
    receipt_signer=signer,
    # Distributed out of band; must equal signer.public_key_hex() exactly (lowercase hex).
    trusted_execution_keys={signer.key_id: public_key_hex},
)
```

Only `generate()` is detected as ephemeral. A key built with the constructor,
`from_seed()` or `from_private_bytes()` is accepted however its bytes were made,
so provisioning the key and its pin is your job.

Grants now expire. Execute within `grant_ttl_seconds` (default 300) of
`issue_grant()`, or raise the TTL. Expiry blocks new executions only: a retry with
the same grant and `execution_attempt_id` is still answered from the ledger. The
ledger is still in-process, so a signed receipt executes only on the instance
that issued it. See the [Runtime Legitimacy Kernel](api/legitimacy.md) reference.

## Also new to 3.0.1 users: the unpublished 3.0.2 changes

3.0.2 was never published, so its changes reach 3.0.1 users for the first time in
4.0.0. Two of them can break a working setup:

- The experimental `gove` optional extra is gone. Install `gove-zone` separately.
- A circuit breaker whose halt-signal directory is missing or fails the trust
  checks now counts as tripped (`GovernanceHaltError`), including the temp-dir
  fallback. Pre-create a trusted signal directory before starting agents, and
  point `ACGS_HALT_SIGNAL_DIR` (or `signal_dir`) at it.

See the 3.0.2 section of the [changelog](changelog.md) for the rest.
