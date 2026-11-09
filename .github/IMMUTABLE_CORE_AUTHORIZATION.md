# Immutable-core repository authorization

Protected repository changes require a delegated maintainer authorization tied
to one repository ID, PR number, main/base commit and PR head commit. This is
account authorization: a maintainer may operate GitHub through an assistant.
It is not proof of human presence or an independent human review. Runtime
principal kinds and the runtime prohibition on non-human core writes do not
change.

## Trust and bootstrap

Install these workflows, the stdlib checker and the policy snapshot through a
separately reviewed prerequisite PR before the control-plane stack. Installation
uses the repository owner's existing authority. It does not claim that a guard
absent from the old base approved its own installation.

`immutable-core-guard.yml` uses `pull_request_target` on main and checks out the
trusted default-branch SHA. Its write-capable token is never used to check out,
install or execute PR code. `python -I` excludes candidate import paths. Actions
are pinned to full commit IDs. The policy snapshot includes the reviewed core
registry and its import-shadow protections, without importing the candidate
control-plane package. The snapshot generator preserves existing restrictions
and the tests require it to cover the current canonical registry.

## Authorize an exact candidate

1. Update the next PR onto current main and make it target main. Run local gates,
   independent review and the hosted CI matrix for its exact head.
2. Fetch the open PR's number, base SHA and head SHA. Dispatch
   `immutable-core-authorize.yml` explicitly on main with those three values:

   ```sh
   gh workflow run immutable-core-authorize.yml --repo acgs-ai/acgs-lite --ref main \
     -f pr_number=NUMBER -f base_sha=BASE_SHA -f head_sha=HEAD_SHA
   ```

   The workflow checks its actual run metadata, allowlisted account identity,
   current repository permission and current PR tuple. A successful run preserves
   one `authorization.json` in the `immutable-core-authorization` artifact.
3. Dispatch `immutable-core-guard.yml` on main with the same inputs, or rerun
   its pending exact-source check. The guard independently validates the
   authorization workflow ID/path, repository ID, trusted source SHA, event,
   branch, initial/rerun actors, first attempt, completion, age, run-linked
   artifact digest and exact JSON binding. A status description or URL cannot
   grant authorization. Missing evidence and incomplete PR-file enumeration deny.
4. Immediately before merge, verify the authentic guard run and authorization
   evidence again, including current account permission, age, PR base/head and
   current main. Merge with the exact head SHA and no admin bypass. If main or
   the PR changes, update, reverify and obtain fresh authorization.

Authorizations expire after the policy's configured lifetime (24 hours). Deleting
the artifact, removing the account from the policy, revoking its repository role,
or changing main/base/head invalidates the authorization. Reruns are not fresh
authorization; dispatch a new authorization run.

## Enforcement scope

Require `immutable-core/guard` and the CI gates on main with strict up-to-date
checks and administrator enforcement. That is defense in depth. Another writable
workflow can emit a similarly named status under the same GitHub Actions App;
therefore the supervised merge procedure must verify the actual trusted workflow
run and evidence, not just the context name. This setup does not claim prevention
against a malicious repository/workflow administrator holding those credentials.
An exact required-workflow organization rule or an isolated external GitHub App
would provide stronger ongoing enforcement and is outside this bootstrap.

Only main-target PRs are supported. Merge the stack sequentially and rebind every
next candidate after main advances. Preserve original authorship and co-author
trailers. Repository authorization does not waive CI, security findings, or
runtime fail-closed enforcement.
