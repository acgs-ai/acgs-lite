# DevPost Submission — Constitutional Sentinel

> GitLab AI Hackathon 2026
> Deadline: March 25, 2026 @ 2:00pm EDT

---

## Project Name

Constitutional Sentinel

## Tagline

An independent GitLab governance agent that reviews AI-generated merge requests, flags risky code inline, flags unsafe merges for blocking (posts a block verdict; enforce via required pipeline + branch protection), and leaves a tamper-evident audit trail.

## Inspiration

AI coding assistants can generate useful code quickly, but they do not understand an organization’s security rules, compliance requirements, or separation-of-duties policies.

That creates a dangerous gap: an AI-generated merge request can hardcode credentials, expose PII, weaken CI controls, or introduce destructive production operations before anyone notices. In many teams, the same person who prompted the AI is also the first person reviewing the code.

We built Constitutional Sentinel to add an independent governance layer to that workflow.

## What it does

Constitutional Sentinel is a GitLab merge request governance agent powered by ACGS-Lite. When a merge request is opened or updated, it:

- **Inspects the merge request diff automatically**
- **Validates added lines against constitutional governance rules** for secrets, PII, destructive SQL, CI bypasses, and separation-of-powers violations
- **Posts inline comments directly on violating lines** so developers can see exactly what needs to change
- **Generates a governance summary** with risk score, violations found, and the constitutional hash of the active ruleset
- **Flags unsafe merges for blocking** (posts a block verdict; enforce via required pipeline + branch protection) when HIGH or CRITICAL violations are present
- **Preserves a tamper-evident audit trail** so reviewers can prove which rules were applied to a specific decision

This is not a chat assistant and not just a linter summary. It is an agent that reacts to GitLab events and takes governance action inside the merge request workflow.

## How we built it

### Governance engine
Constitutional Sentinel runs on **ACGS-Lite**, a Python governance engine with an optional Rust/PyO3 fast path for performance-sensitive validation.

### Constitution format
Rules live in a portable YAML constitution. Each rule includes:
- rule ID
- severity
- category
- keywords
- optional regex patterns

That makes the system adaptable to internal engineering policies as well as regulated environments.

### GitLab workflow integration
We built the GitLab-facing layer to work with real merge request workflows:
- **Webhook handler** for merge request events
- **Diff extraction and per-line validation**
- **Inline MR comments** for precise findings
- **Governance summary report** posted back to GitLab
- **CI/CD stage** that can fail the pipeline when violations are severe enough

### Deployment
The demo is packaged as a stateless container and deployed on **Google Cloud Run**, so it can scale to zero and still respond quickly to merge request events.

### MACI separation of powers
We use a strict three-role model for governance:
- **Proposer** — the AI assistant that writes or suggests code
- **Validator** — Constitutional Sentinel, which reviews independently
- **Executor** — the human who decides whether to merge

That means the system that proposes code is never the system that validates it.

## Challenges we ran into

- **Precision vs. speed:** We needed the system to scan diffs quickly without missing critical issues like credentials or PII.
- **Inline GitLab feedback:** Mapping findings back to the right diff location for comments required careful diff parsing.
- **Stable constitutional hashing:** The active ruleset needed a reproducible fingerprint so governance decisions could be audited later.
- **Making governance visible:** We wanted governance to feel native to the MR workflow, not like an external report nobody reads.

## Accomplishments we're proud of

- **A working end-to-end GitLab MR governance flow** that reacts to events and comments directly on code
- **12 violations caught in a single demo merge request**
- **Block-verdict posting for unsafe changes** (enforced via required pipeline + branch protection)
- **Tamper-evident constitutional hashing and audit trail support**
- **30/30 hackathon evals passing** for the hackathon-focused integration surface
- **A clean demo story judges can inspect directly in GitLab**

## What we learned

- Governance for AI-generated code needs to be **structural, not advisory**
- **Inline feedback beats detached reports** for developer adoption
- **Separation of powers matters in agent workflows**, not just human institutions
- **Performance matters**, but clarity in workflow impact matters even more

## What's next

- Register the Sentinel as a more native **GitLab Duo / flow-style governance step**
- Expand constitutional templates for more compliance and engineering-policy use cases
- Add multi-project governance for GitLab groups
- Expose governance capabilities through MCP and other agent integrations

## Built with

- Python 3.11+
- Rust (PyO3, optional fast path)
- GitLab API
- Starlette / Uvicorn
- YAML constitutions
- Google Cloud Run
- ACGS-Lite

## Try it out

- **GitLab Project**: https://gitlab.com/martin664/constitutional-sentinel-demo
- **Live Demo MR**: https://gitlab.com/martin664/constitutional-sentinel-demo/-/merge_requests/1
- **Constitution**: see `hackathon/constitution.yaml`
- **Video**: https://www.youtube.com/watch?v=uWacmC3CbYg

---

## Submission Checklist

- [ ] Project moved or forked into the GitLab AI Hackathon group
- [ ] Public video uploaded (3 minutes max)
- [ ] Open-source license clearly visible on repo page
- [ ] Demo MR URL verified and public
- [ ] README optimized for judges
- [ ] Devpost form filled out and submitted
