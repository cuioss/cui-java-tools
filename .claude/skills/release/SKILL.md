---
name: release
description: Cut a cui-java-tools release — bump .github/project.yml version, open and merge the release PR, wait for the automated Release workflow, verify the release landed, then reformat the generated GitHub release notes
user-invocable: true
allowed-tools: Bash, Read, Edit
---

# Release Skill

Cuts a new cui-java-tools release end-to-end: determine the version, open the version-bump
PR that triggers the release, merge it, wait for the automated Release workflow, verify the
release landed, and reformat the auto-generated GitHub release notes.

## How the release is wired (read first)

The release is **fully automated by GitHub Actions**. `.github/workflows/release.yml`
triggers on a **merged pull request that changes `.github/project.yml`**:

```yaml
on:
  pull_request:
    types: [closed]
    paths:
      - '.github/project.yml'
```

So this skill never runs Maven release goals by hand. Its job is to produce and merge the
correct `project.yml` change; the reusable `cuioss-organization` release workflow
(`reusable-maven-release.yml`) does the tagging, Maven Central deploy, GitHub release
creation, and — because `pages.deploy-at-release: true` — the documentation pages deploy.

Observed timings (use these as the basis for the waits below):
- PR gating check: **Maven Build ~4–7 min** (matrix over Java 21 + 25). This is a
  zero-dependency library with no integration/e2e suites, so a full green PR is typically
  **~5–8 min**.
- Release workflow itself: **~6 min**, but Maven Central propagation, the GitHub release
  publish, and the pages deploy can lag → allow **up to ~30 min** before treating it as
  stuck.

## Workflow

### Step 1 — Determine the version number

Read the current release block in `.github/project.yml`:
- `release.current-version` (e.g. `2.6.2`) — the **last released** version.
- `release.next-version` (e.g. `2.6-SNAPSHOT`) — the floating development version that
  `pom.xml` carries between releases.

**Default rule (patch line):** cui-java-tools ships three-segment `X.Y.Z` releases
(`2.6.0` → `2.6.1` → `2.6.2` …) while the pom stays permanently on the `X.Y-SNAPSHOT`
minor floor. The release version is therefore `current-version` with the **patch segment
incremented** (`2.6.2` → `2.6.3`), and `next-version` is left **unchanged** (`2.6-SNAPSHOT`).

**Starting a new minor/major line** (e.g. `2.7.0`, `3.0.0`) also bumps `next-version` to the
matching `X.Y-SNAPSHOT` (e.g. `2.7-SNAPSHOT`) and the pom moves with it. That is a deliberate
decision — **ask the user** (AskUserQuestion) before assuming it. Otherwise state the
determined patch version and proceed.

Also **ask the user** if the numbers look inconsistent (e.g. `current-version` doesn't sit on
the `next-version` minor line, or a patch/major release seems intended by recent history).

### Step 2 — Determine current status (clean to release?)

```bash
gh pr list --repo cuioss/cui-java-tools --state open --json number,title,isDraft
```
- **No open PRs** → good, proceed.
- **Open PRs exist** → these would normally be merged before a release. Surface the list
  and **ask the user** whether to proceed anyway or wait. Do not silently ignore them.

Also confirm the working tree is clean (`git status --porcelain`) before branching.

### Step 3 — Pull current main

```bash
git checkout main && git pull --ff-only origin main
```

### Step 4 — Create the release branch

Branch name uses the `chore/` prefix (required — the Maven CI workflow only triggers on
`main`, `feature/*`, `fix/*`, `chore/*`, `release/*`, `dependabot/**`; other prefixes skip
the `build` check and block auto-merge):

```bash
git checkout -b chore/release_<version>   # e.g. chore/release_2.6.3
```

### Step 5 — Update `.github/project.yml`

Edit the `release` block:
- `current-version:` → the version determined in Step 1 (e.g. `2.6.3`).
- `next-version:` → **leave unchanged** for a patch release (stays `2.6-SNAPSHOT`); only bump
  it when starting a new minor/major line (e.g. `2.7-SNAPSHOT`).

Leave everything else untouched. cui-java-tools' README badges (CI, CodeQL, Maven Central,
SonarCloud) are all dynamic endpoints — there is **no** per-release badge to hand-edit.

### Step 6 — Commit, push, open PR

```bash
git add .github/project.yml
git commit -m "chore(release): prepare release <version>"
git push -u origin chore/release_<version>
gh label create skip-bot-review --repo cuioss/cui-java-tools --description "Skip automated bot review" --color ededed 2>/dev/null || true
gh pr create --repo cuioss/cui-java-tools --base main \
  --title "chore(release): prepare release <version>" \
  --label "skip-bot-review" \
  --body "Bump current-version to <version>. Triggers the automated Release workflow on merge."
```

The mechanical release PR carries the `skip-bot-review` label so the automated bot review is
skipped (the label-ensure line above creates it if it does not already exist).

Use the project commit convention: `Co-Authored-By: Claude <noreply@anthropic.com>` (no
model name / no "Generated with Claude Code" footer).

### Step 7 — Wait for PR checks (~5–8 min)

Watch the checks rather than blindly sleeping:

```bash
gh pr checks <pr#> --repo cuioss/cui-java-tools --watch
```
If using a scheduled/loop wait, poll roughly every couple of minutes up to ~8 min.

### Step 8 — Handle PR comments / failures (if any)

- If a check fails, read the failing run's log (`gh run view <id> --log-failed`), fix the
  cause on the branch, push, and re-wait. **Never** merge a red PR.
- If the Gemini reviewer or a human leaves comments (`gh pr view <pr#> --comments`), address
  them on the branch per the repo's PR-comment protocol in `CLAUDE.md`: reply to and resolve
  every comment; ask the user when uncertain.
- Re-run Step 7 after any push.

### Step 9 — Merge → release starts automatically

Once checks are green and comments resolved:

```bash
gh pr merge <pr#> --repo cuioss/cui-java-tools --squash --delete-branch
```
Merging this PR (it touches `.github/project.yml`) fires `release.yml` automatically — do
**not** dispatch the release manually unless the auto-trigger demonstrably did not fire.

### Step 10 — Wait for the Release workflow (~30 min)

```bash
gh run list --repo cuioss/cui-java-tools --workflow "Release" --limit 3 \
  --json status,conclusion,displayTitle,databaseId
# then watch the in-progress run
gh run watch <databaseId> --repo cuioss/cui-java-tools
```
The workflow itself runs ~6 min; allow up to ~30 min for tag + GitHub release publish +
Maven Central propagation + pages deploy before treating it as stuck.

### Step 11 — Verify the release landed

```bash
gh release view <version> --repo cuioss/cui-java-tools \
  --json tagName,name,createdAt,body
git fetch --tags && git tag --list <version>
```
Confirm the tag exists and a GitHub release for `<version>` was created. If it did not
appear, inspect the Release workflow run log before proceeding.

### Step 12 — Reformat the generated release notes

The Release workflow creates the GitHub release with **auto-generated** notes (a flat
`## What's Changed` list). Rewrite them in place using the **house format below**, then
push the update:

```bash
mkdir -p .plan/temp
gh release view <version> --repo cuioss/cui-java-tools --json body --jq .body > .plan/temp/release-<version>-orig.md
# ...build the reformatted body in .plan/temp/release-<version>.md...
gh release edit <version> --repo cuioss/cui-java-tools --notes-file .plan/temp/release-<version>.md
```

#### House format rules (apply exactly)

1. **Two top-level groups:** `## Features & Enhancements` and `## Dependency Updates`.
2. **Features & Enhancements** — group functional PRs by theme with `###` subheadings,
   adapted to cui-java-tools' domain, e.g.:
   - `### Collections` — `collect` builders, literals, `MapDifference`, `MoreCollections`
   - `### Strings & Formatting` — `string` utilities and the `formatting` template engine
   - `### I/O` — file loaders, paths, streams
   - `### Logging` — `CuiLogger`, `LogRecord`
   - `### Net & SSL` — URL/parameter helpers, IDN, keystore/SSL
   - `### Property & Reflection` — `property` / `reflect` helpers
   - `### Lang, Codec & Concurrent` — `LocaleUtils`, `Hex`, ring buffers, `StopWatch`
   - `### API & Code Quality` — public-API changes, refactors, cleanup, and standards
     recipes (e.g. `refactor-to-profile-standards` belongs here, **not** under build/tooling)
   - `### Testing & Standards`
   - `### Documentation`
   Adapt theme headings to the actual PRs; omit empty sections.
3. **Dependency Updates** — group by type with `###` subheadings (cui-java-tools is Java-only
   — there is no JavaScript group):
   - `### Java` — Java libraries (e.g. lombok, junit, cui-test-generator).
   - `### Infra` — platform/build/CI: build plugins, `cuioss-organization` workflow bumps,
     parent-POM / `cui-java-parent` updates.
4. **Collapse version chains** — when the same artifact is bumped multiple times
   (`A → B → C`), keep only the **latest** entry spanning the full range
   (e.g. `lombok 1.18.30 → 1.18.32 → 1.18.34` becomes a single `1.18.30 → 1.18.34`).
5. **Remove all OpenRewrite bumps and friends** — drop every `rewrite-maven-plugin`,
   `rewrite-migrate-java`, `rewrite-testing-frameworks`, and related OpenRewrite dependency PR.
6. **Remove internal tooling churn** — drop PRs that only touch dev/build orchestration with
   no user-facing effect: `marshal.json`/plan-marshall config migrations, plan-marshall build
   wiring, internal dev-skill changes, and the mechanical version-bump PR itself.
7. Preserve each kept PR line verbatim (`* <title> by @author in <url>`); when two PRs share
   an identical title, merge them onto one line with both URLs.
8. Keep the trailing `**Full Changelog**: ...compare/<prev>...<version>` line.

### Step 13 — Done
