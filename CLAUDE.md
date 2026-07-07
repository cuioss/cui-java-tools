# CLAUDE.md

Guidance for Claude Code (and other AI tools) when working in this repository.

## Project Overview

`cui-java-tools` is a **zero-dependency** Java utility library — a curated replacement
for parts of Guava and Apache Commons, following Jakarta EE conventions. Lombok is the
only compile-time dependency (dev-only, not transitive).

- Maven coordinates: `de.cuioss:cui-java-tools`
- Java module: `de.cuioss.java.tools` (`src/main/java/module-info.java`)
- Java release: **21** (`maven.compiler.release`)
- Current version: see `<version>` in `pom.xml` (floats on the `X.Y-SNAPSHOT` minor line between releases)
- Published on **Maven Central** — public API changes require deliberate consideration.

## Build & Test

Always build and test through Maven. **Never** invoke `javac` directly or write ad-hoc
`main`/verifier classes outside JUnit.

- Build: `./mvnw clean install`
- Test: `./mvnw test`
- Single test: `./mvnw test -Dtest=ClassName#methodName`
- Coverage: `./mvnw -Pcoverage verify`
- Pre-commit gate (run before every commit): `./mvnw -Ppre-commit clean verify`
  - Fix **all** errors and warnings.
  - OpenRewrite recipes may add markers or rewrite sources — either accept the rewrite or
    suppress with justification. **Never commit rewrite markers**, and never leave the tree
    dirty after a pre-commit run.

## Architecture

Main source under `src/main/java/de/cuioss/tools/`, tests mirror it under `src/test/java/`.

- `base` — `Preconditions`, `BooleanOperations`
- `collect` — collection builders, literals, `MoreCollections`, `MapDifference`
- `string` — `Joiner`, `Splitter`, `MoreStrings`, `TextSplitter`
- `io` — file loaders, `MorePaths`, `FilenameUtils`, `IOStreams`
- `logging` — `CuiLogger` framework (wraps `java.util.logging`)
- `net` / `net.ssl` — URL/parameter helpers, IDN, keystore & SSL utilities
- `lang` — `LocaleUtils`, `MoreObjects`
- `concurrent` — `StopWatch`, `ConcurrentTools`, ring buffers
- `formatting` — template-based formatting (lexer / token / template)
- `codec` — `Hex`
- `property` / `reflect` — type-safe property access and reflection helpers

### Design principles

- Zero external runtime dependencies.
- Facade/decorator over standard Java rather than full reimplementation.
- Builders for complex construction; immutable objects where possible.
- Every code-bearing package has a `package-info.java`.

## Logging

- Use `de.cuioss.tools.logging.CuiLogger` — declare as `private static final CuiLogger LOGGER`.
- No `slf4j`, `log4j`, `System.out`, or `System.err`.
- Placeholders use `%s` (and `{}` is also supported); the exception parameter always comes
  **first** in logging methods.
- Use `de.cuioss.tools.logging.LogRecord` for templated, catalogued messages.
- Message-identifier ranges: **INFO 001–099, WARN 100–199, ERROR 200–299** (there is no
  FATAL level). Catalogued messages are documented in `doc/LogMessages.adoc`.

## Testing

- JUnit 5 only. **Forbidden: Mockito, PowerMock, Hamcrest** — use the CUI alternatives.
- Follow AAA (Arrange-Act-Assert); tests must be order-independent.
- Use the **cui-test-generator** for test-data generation and `cui-test-value-objects` for
  value-object contract tests.
- Use `cui-test-juli-logger` (`@EnableTestLogger`, `assertLogMessagePresentContaining`) for
  logging assertions.
- Prefer `@ParameterizedTest` for 3+ similar variants.
- All public APIs must be tested; keep coverage at or above the project gate (80% line/branch).

## Null-safety (JSpecify)

JSpecify is a dependency. Adoption is **in progress** — currently only
`de.cuioss.tools.logging` is `@NullMarked`. When touching a package, prefer marking it
`@NullMarked` at the `package-info.java` level and annotating the exceptions with
`@Nullable`. Note Lombok `@NonNull` (runtime check) and JSpecify (static contract) are
complementary, not interchangeable.

## API & Deprecation Policy

- Since this is published on Maven Central, treat public API changes deliberately.
- API removals go through a deprecation cycle: mark with
  `@Deprecated(since = "<version>", forRemoval = true)` and remove only in the next major
  release. Do **not** delete public members (including enum constants) outright.
- Remove unused **internal** code directly.

## Git Workflow

`main` is branch-protected — **never push to `main` directly**.

1. Branch: `git checkout -b <prefix>/<name>` (prefixes that trigger CI: `feature/*`,
   `fix/*`, `chore/*`, `release/*`).
2. Commit: `git add <files> && git commit -m "<message>"`.
   - End commit messages with: `Co-Authored-By: Claude <noreply@anthropic.com>`
     (no model name, no "Generated with Claude Code" footer).
3. Push: `git push -u origin <branch>`.
4. PR: `gh pr create --repo cuioss/cui-java-tools --head <branch> --base main --title "<title>" --body "<body>"`.
5. Wait for CI + Gemini review:
   `while ! gh pr checks --repo cuioss/cui-java-tools <pr> --watch; do sleep 60; done`.
6. Address every review comment (fix or explain, then resolve). If uncertain about a
   comment, ask the user before acting.
7. Do **not** enable auto-merge unless explicitly told to.
8. After merge: `git checkout main && git pull`.

## Releases

Releases are fully automated by GitHub Actions. A release is cut by bumping
`.github/project.yml` `release.current-version` (patch bump on the `X.Y.Z` line, e.g.
`2.6.2` → `2.6.3`) in a merged PR — the `pom.xml` stays on the floating `X.Y-SNAPSHOT` minor line.
Use the `/release` skill (`.claude/skills/release/`); never run Maven release goals by hand.

## Process Rules

- If in doubt, ask the user — don't guess or invent APIs/standards.
- Research current best practices with the available tools before proposing changes.
- Don't add dependencies without approval.
- Don't proliferate documents — reuse existing ones; create new docs only when asked.
- Use the JetBrains MCP only for per-file IDE diagnostics, not for other tasks.
- Use the `gh` CLI for all GitHub access.
