# Hero Demo Capture Plan for `acgs-lite`

Date: 2026-04-10

Goal: create a short terminal GIF that proves the core wedge in under 20 seconds.

## Primary message

`acgs-lite` blocks unsafe agent actions before execution.

## Asset placement

Final asset path:
- `docs/assets/basic-governance-hero.gif`

README placement:
- directly below the top positioning paragraph
- above the fold, before `Start here in 3 minutes`

## Exact story arc

The GIF should show three outcomes in sequence:

1. safe request passes
2. harmful request is blocked
3. PII-like request is blocked

That gives a clean visual proof of:
- allow
- block
- block

## Preferred source

Use:
- `examples/basic_governance/main.py`

Why:
- no API keys
- fast to run
- already aligned with README positioning
- produces the exact proof we want

## Terminal framing

Recommended terminal title or opener:
- `acgs-lite: block unsafe actions before execution`

Keep the frame tight:
- repo root visible once
- command visible once
- output centered and readable

## Capture sequence

From package root:

```bash
python examples/basic_governance/main.py
```

Ideal visible output emphasis:

```text
✅  Allowed:  Response to: What is the capital of France?
🚫  Blocked:  no-harmful-content — Block requests containing harmful keywords
🚫  PII gate: no-pii — Prevent PII leakage in requests
```

## Editing rules

- Trim dead time before command execution
- Speed up pauses, but keep output readable
- Keep total runtime around 12 to 20 seconds
- Crop to terminal only
- No cursor wandering
- No extra shell noise
- No dependency install steps in the GIF

## Export targets

Preferred:
- GIF for README above the fold

Optional companions:
- MP4 for X / Reddit
- full terminal recording for reuse in docs

## Supporting copy for README

Hero caption:
- `20-second proof: a safe request passes, unsafe requests get blocked before execution.`

Alt text:
- `Terminal demo of acgs-lite allowing a safe request and blocking harmful and PII-like requests before execution.`

## Follow-up after asset exists

1. save GIF to `docs/assets/basic-governance-hero.gif`
2. replace README placeholder comment with live image block
3. optionally export MP4/social variants from the same source capture
