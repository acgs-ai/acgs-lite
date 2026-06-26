# Security Policy

ACGS-Lite is governance infrastructure for checking proposed side effects before
execution. This policy describes the intended responsible-disclosure process for
security issues in that governance boundary. It does not claim certification,
production readiness, or a guarantee that every deployment using ACGS-Lite is
secure.

## Supported Versions

Only the current packaged version line is targeted for security fixes.

| Version line | Security status | Notes |
| --- | --- | --- |
| `2.10.x` | Supported for responsible-disclosure triage and intended fixes | Current published package version is `2.10.1`; the `2.11.0` release remains pending publication. |
| `< 2.10` | Not supported | Upgrade to the latest `2.10.x` release before reporting unless the issue also affects `2.10.x`. |

## Vulnerability Scope

Security reports should focus on defects that could weaken or bypass the
governance membrane. In scope examples include:

- executing a side effect without a valid allow receipt, or accepting a receipt
  that does not match the requested method, scope, subjects, policy version, or
  execution boundary;
- a fail-closed bypass where missing, stale, malformed, or unverifiable
  authorization is treated as permission to proceed;
- a MACI bypass that lets one actor collapse proposer, validator, executor, or
  observer separation in a way the library treats as valid;
- tampered audit evidence, forged decision history, or replay evidence accepted
  as valid;
- a constitution or constitutional-hash mismatch accepted as the active policy;
- secret or sensitive prompt data being exposed through ACGS-Lite logs, errors,
  reports, or integration wrappers;
- dependency or packaging behavior that lets an attacker subvert ACGS-Lite's
  validation, receipt, audit, or lifecycle boundaries.

Out of scope for this policy:

- vulnerabilities only in a host application, model provider, agent framework, or
  deployment environment that do not require an ACGS-Lite defect;
- social-engineering, spam, denial-of-service by high-volume traffic, or physical
  attacks;
- reports that require publishing exploit playbooks, weaponized payloads, or
  step-by-step bypass recipes.

## Private Disclosure Channel

Please report suspected vulnerabilities privately by email:

`security@acgs.ai`

Do not open a public GitHub issue for a suspected security vulnerability. The
intended reporting path is:

1. Send a concise description of the suspected issue and affected ACGS-Lite
   version.
2. Include the relevant configuration, integration path, and observed impact.
3. If needed, include a minimal non-destructive proof of concept or reproduction
   summary. Avoid production secrets, personal data, weaponized payloads, and
   instructions that would enable abuse.
4. Share any public-disclosure timing constraints so coordination can happen
   before details are published.

## Response Windows

These are the project's disclosure commitments, not a statement that the channel
has independent staffing or external certification.

| Stage | Window |
| --- | --- |
| Acknowledgement | Aim to acknowledge receipt within 48 hours. |
| Assessment | Aim to complete an initial severity and scope assessment within 5 business days. |
| Fix target | Aim to publish or prepare a fix within 30 days for confirmed critical/high issues, with lower-severity issues scheduled based on risk and release capacity. |
| Coordinated public disclosure | Aim to coordinate public disclosure after a fix or mitigation is available, normally within 90 days of the initial report unless reporter safety, active exploitation, or dependency coordination requires a different timeline. |

## Public Disclosure

Please keep vulnerability details private until a fix, mitigation, or coordinated
advisory is ready. Public advisories should describe impact, affected versions,
fixed versions, and defensive guidance without publishing step-by-step exploit
instructions.
