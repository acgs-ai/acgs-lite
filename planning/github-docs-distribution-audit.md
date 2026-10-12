# GitHub, documentation, and distribution audit

Audit date: 2026-10-12. Repository: `acgs-ai/acgs-lite`.
Base: `e6b6f597fda033770f4a14a43255da122986986e` from `origin/main`.
Working branch: `codex/docs-distribution-community`.

## Scope and execution plan

Review the public GitHub entry point and current source; improve the documentation
home and navigation; document existing installation/distribution channels; add
community pages and GitHub forms; prepare social launch drafts; independently
review and validate the result. Runtime enforcement and release versions are outside
the change. The original local main was 71 commits behind; work began on a new branch
from refreshed origin/main with a clean working tree.

## Findings and disposition

| Finding | Evidence | Disposition |
| --- | --- | --- |
| Release surfaces describe different artifacts | PyPI JSON reports 3.0.1; GitHub latest Release is v2.12.0; README labels source-only hardening unreleased | Preserve the distinctions in installation, home, FAQ, and launch copy; no version bump |
| Quickstart output did not match its code | README caught the exception silently but displayed it as expected output | Print the exception; verify against both PyPI 3.0.1 and the locally built wheel |
| Installation and community routes were scattered | Existing MkDocs nav and repository community files | Add installation catalog, community hub, FAQ, walkthrough guide, and navigation cards |
| DSPy advertised an undefined extra | No `dspy` extra in pyproject; example README and script advertised one | Document/install the separate optional dependency; correct script output |
| Adapter claims exceeded the shown execution path | Integration source wrappers and streaming methods | Replace unsupported production labels; explain observational outputs, streaming limits, and actual constructor wiring |
| GitHub community intake lacked routing/forms | Discussions enabled; GraphQL confirms `q-a`, `ideas`, `show-and-tell` slugs | Add issue contact links and Q&A/showcase forms; preserve private security routing |
| Container source selection omitted package metadata | Dockerfile copied pyproject/src only; isolated equivalent wheel had an empty README body and no LICENSE | Copy README and LICENSE; exclude local environments/site output from build context |
| Docs requested a missing version index | Local browser requested `/versions.json` and received 404 | Disable the unbacked selector; rebuilt page makes no such request |
| Public docs route is not this MkDocs build | HTTP `/docs/` redirects to `/resources/` | Record deployment gap; use GitHub-hosted references in draft campaign |
| Security support table is stale | SECURITY.md names 2.12.x as current while PyPI reports 3.0.1 | Leave supported-version policy for maintainer decision; no inferred support promise |

Live reference endpoints: [GitHub repository](https://github.com/acgs-ai/acgs-lite),
[PyPI metadata](https://pypi.org/pypi/acgs-lite/json),
[GitHub Releases](https://github.com/acgs-ai/acgs-lite/releases), and
[public documentation entry](https://acgs.ai/docs/).
The GitHub Pages API returned 404; this alone does not establish whether a site is configured.
The source commit's existing CI succeeded; it is not CI evidence for these local edits.

## Handoff — codex/docs-distribution-community / acgs-lite

**What changed:** Redesigned documentation entry and navigation; added installation
and community content; corrected adapter/install claims; improved community intake;
fixed container package metadata; prepared social launch drafts.

**Directories touched:**

- Repository root, `docs/`, `.github/`, `examples/`, `planning/`: root AGENTS and
  package guidance loaded; no nearer instructions or independent git boundary in these scopes.

**Files touched:**

- Root: `.dockerignore`, `Dockerfile`, `README.md`, `CONTRIBUTING.md`, `mkdocs.yml`.
- Docs: `index.md`, `installation.md`, `community.md`, `community/faq.md`,
  `community/share-a-walkthrough.md`, `contributing.md`, `integrations.md`,
  `integration-decision-guide.md`.
- GitHub: `ISSUE_TEMPLATE/config.yml`, `ISSUE_TEMPLATE/bug_report.yml`,
  `DISCUSSION_TEMPLATE/q-a.yml`, `DISCUSSION_TEMPLATE/show-and-tell.yml`.
- Examples: `agent_quickstart/README.md`, `dspy_governance/README.md`,
  `dspy_governance/run.py`, `membrane_5min.py`.
- Planning: `README.md`, `social-launch-kit.md`, this report.

**Subagents run:**

- Planning: `docs_plan` (chat implementation plan; child artifact write unavailable).
- Implementation: `docs_author`, `distribution_audit`, `distribution_fix`,
  `social_content`; parent integrated proposed patches where child writes were denied.
- References: `community_research`, official GitHub and Material documentation.
- Review: separate `independent_review`; no remaining blocking findings.
- Verification: separate `final_verification`, plus parent browser and PyPI snippet checks.

**Hash-marked or sealed files touched:** Documentation and DSPy example contain the
existing constitutional hash marker; its value is unchanged. No sealed policy,
hash computation, or runtime enforcement changed. SECURITY.md was left unchanged.

**Generated files touched:** No tracked generated sources edited. `make build` and
MkDocs generated ignored wheel/sdist, build intermediates, and `site/docs/` output.

**Submodule or nested repo touched:** No; topology inspection confirmed a single git root.

**Tests / checks run:**

```text
rtk proxy make verify PYTHON=.venv/bin/python
All checks passed!
Success: no issues found in 314 source files
6414 passed, 343 skipped, 3 deselected, 1 xfailed, 30 warnings in 27.06s
targeted-tests: passed — 54 passed in 0.28s
verify: all gates passed
EXIT 0

rtk proxy make build PYTHON=.venv/bin/python
Successfully built acgs_lite-3.0.1-py3-none-any.whl and acgs_lite-3.0.1.tar.gz
EXIT 0

rtk proxy .venv/bin/python -m twine check dist/acgs_lite-3.0.1-py3-none-any.whl dist/acgs_lite-3.0.1.tar.gz
Both distributions: PASSED
EXIT 0

MKDOCS_GIT_REVISION_DATE_ENABLED=false .venv/bin/python -m mkdocs build --strict
Documentation built in 2.79 seconds
EXIT 0

rtk proxy .venv/bin/python scripts/check_links.py
All documentation links resolve.
EXIT 0

rtk proxy .venv/bin/python examples/dspy_governance/run.py
Recorded 3 entries; chain intact: True
EXIT 0

rtk proxy git diff --check
EXIT 0
```

Fresh installed wheel verification checked import location, version 3.0.1, CLI help,
README snippet output, `pip check`, all three workflow YAML assets, all 27 declared
extras, and the bundled Apache-2.0 license. The README's published-package snippet
also passed against a separately installed PyPI 3.0.1 wheel.

Browser checks covered the landing, installation, and community pages at desktop
and 390px mobile widths: navigation/content rendered, four landing cards were
present, and no horizontal page overflow was observed. After the selector fix,
the landing made zero `versions.json` requests.

Evidence logs: `/tmp/acgs-docs-final-verify.log`, `/tmp/acgs-docs-final-build.log`,
`/tmp/acgs-docs-final-mkdocs.log`; installed-wheel evidence under
`/tmp/acgs-docs-wheel-a67k1yva/`; container metadata reproduction under
`/tmp/acgs-docker-metadata-u4hrht8h/`.

**Workflows expected to gate this change:** `.github/workflows/ci.yml`;
local `make verify`, strict MkDocs, wheel/sdist build and Twine. Future publication
uses the separate `release-candidate.yml` and `publish.yml` qualification gates.

**Risk class:** yellow — local changes pass; deployment and support-policy gaps remain.

**Not run / not verified:**

- Full Docker build/runtime: Docker socket access denied. Isolated equivalent
  source-context builds verified the metadata correction only.
- Remote CI for this diff, merge, PyPI upload, website deployment, and social
  posting: not performed. New pages/forms are local until merged/deployed.
- The test counts above record the original audit snapshot. The subsequent
  [skip remediation](test-skip-remediation.md) resolves its dependency, stale-API,
  and research-fixture gaps with a 6,828-case run without skips, xfails, or
  deselection. No cross-platform Rust wheel build was attempted.
- Security support-window policy needs maintainer resolution. Existing legal
  mapping pages were not re-certified or subjected to a fresh legal audit.

**Next:** Review the local diff and launch kit, resolve the support-policy and
website-delivery decisions, then merge/deploy through the existing gates.
