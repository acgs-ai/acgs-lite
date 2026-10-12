# Frequently asked questions

## Which version should I use for a tutorial?

Match the tutorial to its stated artifact. The public package is 3.0.1; the source
candidate contains additional execution-grant and recovery hardening. Because the
source metadata can still say 3.0.1, include the Git commit when reporting source
results. [Installation and distributions](../installation.md) explains the distinction.

## Why can't I run `python examples/membrane_5min.py` after installing with pip?

`examples/` belongs to the repository and is not shipped in the wheel. Run the
pip-only snippet in the [5-minute guide](../guides/five-minute-membrane.md), or clone
the repository before running its examples.

## Does a successful model call prove the tool action was authorized?

No. An SDK wrapper checks the inputs and outputs it sees. A later shell command,
HTTP write, or payment needs its own governed execution path. Identify the actual
side-effect function, connect the authorization check there, and test that denial
leaves its invocation counter unchanged. See [runtime legitimacy](../api/legitimacy.md).

## Why did an adapter return output with a policy violation?

Several adapters validate completed output with `strict=False` and log warnings;
that is observational output validation. It does not withhold the response.
Streaming paths may validate input only. Read the [adapter guide](../integration-decision-guide.md)
and the relevant implementation before choosing an enforcement boundary.

## Does `acgs-lite[all]` install every feature?

No. It is a named convenience bundle. The current manifest excludes `server`,
`postgres`, `gove`, `docs`, and `dev` from that bundle, and some third-party
frameworks require separate installs. The [extras table](../installation.md#optional-dependencies)
is the source-checkout catalog. Optional SDKs can impose stricter Python requirements.

## Is the audit trail a managed storage service?

No. Storage depends on the backend you select and operate. An in-memory chain
can demonstrate tamper evidence within that process; it does not establish durable
storage, cross-process exclusion, or restart recovery. The source candidate's
production profile adds requirements documented in the [audit](../api/audit.md)
and [legitimacy](../api/legitimacy.md) references.

## Do the compliance mappings certify my application?

No. They are self-assessed mappings to help structure review. They do not establish
certification, regulator approval, or compliance for your deployment. See
[Compliance](../compliance.md) for scope and limitations.

## I found a bug. What makes a useful report?

Provide the package version or commit, Python version, installed extras, minimal
code, expected result, actual result, and exact command. For a denied action,
include evidence of whether the side-effect function ran. Remove secrets and
private inputs; send suspected vulnerabilities through the [security policy](../security.md).

## Where do I check distribution and website delivery?

See [Installation and distributions](../installation.md#distribution-surfaces)
for the Python package, optional Rust artifacts, container, documentation build,
and website delivery paths.
