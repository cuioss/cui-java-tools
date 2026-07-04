# Project Analysis Findings

Full-project analysis performed on 2026-07-03 (baseline: `main`, 2.6-SNAPSHOT, build green).
Each finding has a stable ID, a severity, the planned resolution, and the PR cluster that addresses it.
This document is removed once every finding is verified as fixed.

Resolution legend: **code** = change implementation, **doc** = fix documentation to match reality,
**test** = add/repair tests, **remove** = delete dead code/config.

## Cluster A — Documentation & build hygiene (PR 1)

| ID | Location | Sev | Finding | Resolution |
|----|----------|-----|---------|------------|
| DOC-1 | CLAUDE.md:32 | M | Claims version 2.4.1-SNAPSHOT; pom is 2.6-SNAPSHOT | doc |
| DOC-2 | CLAUDE.md:78 | M | "PRE-1.0 project" claim stale at 2.6-SNAPSHOT | doc |
| DOC-3 | CLAUDE.md:80 | M | "No deprecation annotations" contradicted by `PropertyUtil.writeProperty` `@Deprecated(forRemoval=true)` | doc |
| DOC-4 | CLAUDE.md:69 | M | "Uses Hamcrest" — Hamcrest absent and forbidden per doc/ai-rules.md | doc |
| DOC-5 | CLAUDE.md:15,42 | M | Claims HTTP utilities; no `net.http` package exists | doc |
| DOC-6 | README.adoc:707-713 | H | Documents nonexistent `de.cuioss.tools.net.http` package (HttpHandler, HttpStatusFamily, SecureSSLContextProvider) | doc |
| DOC-7 | README.adoc:379 | M | Example uses `sleepUninterruptibly`; actual method is `sleepUninterruptedly` | doc |
| DOC-8 | README.adoc:53 | L | Broken link to CODE_OF_CONDUCT.md | doc |
| DOC-9 | formatting/, net/ssl/ | M | Missing package-info.java (mandated by project rules) | code |
| DOC-10 | de/cuioss/tools/package-info.java | L | Says "Built on Java 17"; release is 21 | doc |
| BUILD-1 | pom.xml:89-93 | M | jakarta.annotation-api scope `provided` but only test code uses it; contradicts dependencyManagement `test` pin | code |
| BUILD-2 | pom.xml:31 | L | `Automatic-Module-Name` property looked dead (real module-info.java exists) — verified NOT removable: the parent pom's jar-plugin config requires it (invalid default derived from artifactId breaks the build). Documented in place instead | doc |
| BUILD-3 | module-info.java:21 | L | `requires java.net.http` unused by main sources | remove |
| BUILD-4 | module-info.java:23-38 | L | Root package `de.cuioss.tools` (public `ToolsLogMessages`, documented in doc/LogMessages.adoc) not exported | code |

## Cluster B — Logging (PR 2)

| ID | Location | Sev | Finding | Resolution |
|----|----------|-----|---------|------------|
| LOG-1 | LogLevel.java:125 | H | `doLog` passes user Throwable to `findCallerElement` → scans exception's stack → wrong source class/method for every log call with a Throwable | code |
| LOG-2 | CuiLogger.java:721 + LogLevel.java:113 | H | `getLogLevel()` NPEs when `Logger.getLevel()` is null (inherited level — the default); `LogLevel.from(null)` NPEs | code |
| LOG-3 | CuiLoggerFactory.java:82 | M | `findCallerInternal` guard `length < 5` off-by-one; `getLogger()` from bottom-of-stack method throws | code |
| LOG-4 | LogRecordModel.java:132 | M | Class doc claims "All builder parameters are validated for null"; no validation exists | code (add validation) |
| LOG-5 | LogLevel.java:110 | L | First sort in `LogLevel.from` immediately discarded by second sort | remove |
| LOG-6 | ToolsLogMessages.java:31 | L | Documents "300-399: FATAL level"; no FATAL level exists | doc |
| LOG-7 | CuiLoggerTest.java:137 | M | No assertions on sourceClassName/sourceMethodName (why LOG-1 went undetected) | test |
| LOG-8 | CuiLoggerTest.java:105 | L | `getLogLevel()` default (inherited/null level) untested | test |
| LOG-9 | LogRecordModelTest.java:27 | L | `LogRecord.supplier(Object...)` never exercised | test |
| LOG-10 | TestLogHandler.java:31 | L | Field `lastLevel` never used | remove |

## Cluster C — Collections (PR 3)

| ID | Location | Sev | Finding | Resolution |
|----|----------|-----|---------|------------|
| COL-1 | MapDiffenceImpl.java:137 | H | `ValueDifferenceImpl` lacks equals/hashCode/toString; violates documented `MapDifference.ValueDifference` contract; cross-instance `MapDifference.equals` broken | code |
| COL-2 | PartialArrayList.java:39-41 | M | `@EqualsAndHashCode(callSuper=true)` creates asymmetric equals vs plain List, violates `List` contract | code |
| COL-3 | MoreCollectionsTest.java:46 | M | `shouldDetermineEmptinessForArrays()` missing `@Test`, never runs and would fail (primitive array varargs pitfall) | test |
| COL-4 | collect/package-info.java:59 | M | Example `new PartialArrayList<>(originalList, 0, 3)` doesn't compile; "view" claim wrong | doc |
| COL-5 | MapBuilder.java:241 | M | `toImmutableMap()` wraps live internal map without copy — mutation backdoor | code |
| COL-6 | CollectionLiterals.java:127 | M | `mutableList(E)` keeps null while all sibling single-element factories drop it | code |
| COL-7 | CollectionLiterals.java:793 | M | `immutableMap(Map)` wraps without copy (mutability leak); NPEs on null while siblings tolerate null | code |
| COL-8 | CollectionBuilder.java:506 | L | `toArray(Class<? super E>)` unsafely casts to `E[]`; supertype token → ClassCastException at call site | code |
| COL-9 | CollectionBuilder.java:605 | L | `copyFrom(E)` with null adds a null element; all other overloads yield empty builder | code |
| COL-10 | CollectionBuilder.java:226 | L | `contains` doc references `Collection#isEmpty()` | doc |
| COL-11 | CollectionBuilder.java:417-421 | L | `toImmutableSet()` doc claims `unmodifiableList(List)` | doc |
| COL-12 | CollectionLiterals.java:422 | L | `immutableSet()` doc claims "newly created empty HashSet" | doc |
| COL-13 | CollectionLiterals.java:777 | L | `immutableMap()` doc says "empty mutable Map" | doc |
| COL-14 | CollectionLiterals.java (multiple) | L | `immutable*` docs say "must not be null" though null tolerated; garbled "null an empty" texts | doc |
| COL-15 | MapBuilder.java:147-159 | L | `put`/`putIfNotNull` docs claim nonexistent "must not be empty" constraints | doc |
| COL-16 | MapDifference.java:70-78 | L | Documented hashCode formula doesn't match implementation | doc |
| COL-17 | MapDiffenceImpl.java:35 | L | Class name misspelled ("Diffence"); comment references nonexistent "MapDifferenceImpl" | code (rename) |
| COL-18 | MoreCollectionsTest.java:43 | L | `requireNotEmpty(0, MESSAGE)` swallows MESSAGE into varargs; passes for wrong reason | test |
| COL-19 | MoreCollectionsTest.java | L | No tests for MapDifference equals/hashCode, toImmutableMap aliasing, toArray token | test |

## Cluster D — Strings & formatting (PR 4)

| ID | Location | Sev | Finding | Resolution |
|----|----------|-----|---------|------------|
| FMT-1 | BracketLexer.java:139-148 | H | Balanced templates with static text on exactly one side falsely rejected as "unbalanced" (Splitter drops trailing empties) | code |
| FMT-2 | TemplateFormatterImpl.java:91-133 | H | `format()` silently drops leading and trailing static text | code |
| FMT-3 | ActionToken.java:55-61 | M | `template.split(token)` treats attribute name as regex; metacharacters break/throw | code |
| FMT-4 | SimpleFormatter.java:111 | L | Filter uses `MoreCollections.isEmpty(Object...)` on single String — always false, dead filter | code |
| FMT-5 | Lexer.java:107-122 | L | `ExpressionLanguage.STEL` unusable via any code path; `SIMPLE_SQUARED_BRACKTES` typo is public API | doc/remove |
| FMT-6 | lexer/token/template package-info | L | Usage examples are fabricated APIs (`LexerBuilder.create()`, `tokenize()`, 1-arg `ActionToken`, placeholder block); broken package links | doc |
| FMT-7 | Validator.java:42-46 | L | Garbled `@param`/missing `@throws` documentation | doc |
| FMT-8 | TemplateFormatterTest.java:184-189 | L | Empty test without `@Test`; no test formats template with static prefix/suffix (why FMT-1/2 undetected); `"M\00FCller"` octal-escape typo | test |
| STR-1 | MoreStrings.java:236-245 | M | `unquote("'")`/`unquote("\"")` throws StringIndexOutOfBoundsException | code |
| STR-2 | Splitter.java:301 | M | `Splitter.on(Pattern)` recompiles from pattern source, discarding flags (CASE_INSENSITIVE etc.) | code |
| STR-3 | Splitter.java:249-270 | M | `doNotModifySeparatorString()` is a functional no-op; every doc claim about it wrong; config flag never read | code (honor flag) |
| STR-4 | Splitter.java:287-312 | M | Trailing empty segments always removed, leading kept — undocumented asymmetric behavior | doc |
| STR-5 | MoreStrings.java:1214-1232 | M | `coalesce` doc inverted (predicate is a rejector, not acceptor); NPE for non-rejected null undocumented | doc |
| STR-6 | string/package-info.java:64,85-89 | M | Examples use nonexistent `nullToDefault`, `skipEmpty()`; claimed output impossible; "{} placeholders" claim wrong | doc |
| STR-7 | MoreStrings.java:130 | L | Example claims `countMatches("banana","a") == 2`; is 3 | doc |
| STR-8 | MoreStrings.java:358-471 | L | `isPresent`/`isNotBlank` example blocks labeled with wrong method names; `isNumeric` block malformed | doc |
| STR-9 | MoreStrings.java:1166 | L | `lenientFormat` unconditionally logs wrong FINE message on every invocation (hot path) | remove |
| STR-10 | MoreStrings.java:1175-1177 | L | `requireNonNull` unreachable after Lombok `@NonNull` | remove |
| STR-11 | TextSplitter.java:46-64,116-163 | M | "Immutable" claim false; `isAbridged()` wrong before `getAbridgedText()` (lazy side effect); ctor null-handling inconsistent; class examples wrong | code+doc |

## Cluster E — I/O (PR 5)

| ID | Location | Sev | Finding | Resolution |
|----|----------|-----|---------|------------|
| IO-1 | UrlLoader.java:81-104 | H | Cached URLConnection returns same stream; `isReadable()` closes it → subsequent `inputStream()` unusable; violates FileLoader reentrancy | code |
| IO-2 | ClassPathLoader.java:137-143 | M | TCCL fallback passes leading-slash name to `ClassLoader.getResource()` — fallback dead | code |
| IO-3 | MorePaths.java:239-241 | M | `backupFile` NPEs for single-segment relative path (null parent) | code |
| IO-4 | MorePaths.java:359 | M | `deleteQuietly`: `File.list()` null → NPE, contradicting "never throws" | code |
| IO-5 | FileSystemLoader.java:153-161 | M | `outputStream()` doc claims file creation; `writable` frozen at construction requires existing file | doc |
| IO-6 | FileSystemLoader.java:124-131 | M | `external:` handling: IOException swallowed → nonsense path; missing separator; prefix undocumented | code |
| IO-7 | FileLoaderUtility.java:99 + MorePaths.java:289 | L | Temp-file suffix passed without dot → extension mangled (`report...txt` → `...886txt`) | code |
| IO-8 | io/package-info.java:53-81 | M | Examples call nonexistent methods (`readFromClasspath`, `checkReadableFile`, `loadFileFromPath`) | doc |
| IO-9 | UrlLoader.java:34-57 | L | Class doc describes opposite behavior; ctor `@throws` text inverted | doc |
| IO-10 | IOCase.java:67,106-108 | L | `readResolve()`/`transient` no-ops for enums | remove |
| IO-11 | IOStreams.java:161-167 | L | `toString(InputStream)` declares NPE but throws IAE; mentions nonexistent encoding param | doc |
| IO-12 | FileWriter.java:41-44 | L | `outputStream()` doc says "not readable" (copy-paste) | doc |
| IO-13 | FilenameUtils.java:540 | L | `concat` example result missing leading slash | doc |
| IO-14 | MorePaths.java:454-479 | L | `saveAndBackup` leaks temp file; doc references nonexistent `PathUtils` | code+doc |
| IO-15 | IOCase.java:197-200 | L | `checkEndsWith` zero coverage | test |
| IO-16 | UrlLoaderTest.java:53-63 | M | Nothing reads via `UrlLoader.inputStream()`; reentrancy untested (masked IO-1) | test |

## Cluster F — Networking & SSL (PR 6)

| ID | Location | Sev | Finding | Resolution |
|----|----------|-----|---------|------------|
| NET-1 | UrlParameter.java:306 | M | `createNameValueString(true)` double-encodes already-encoded stored fields | code |
| NET-2 | UrlParameter.java:254-271 | M | `fromQueryString` drops params whose value contains `=`; `"=foo"` misparsed | code |
| NET-3 | UrlParameter.java:134-141 | L | `createParameterString` null handling inconsistent (first null → "", later null → NPE) | code |
| NET-4 | UrlParameter.java:214-215 | L | `createParameterMap` doc claims one-element list; null value yields empty list | doc |
| NET-5 | UrlHelper.java:144-153 | M | `isValidUri(null/"")` returns true, contradicting javadoc and `tryParseUri` | code |
| NET-6 | ParameterFilter.java:40 | M | Faces exclusion only matches `javax.faces`; Jakarta Faces uses `jakarta.faces` | code |
| NET-7 | ParameterFilter.java:64 | L | `toLowerCase()` default locale (Turkish-i problem) | code |
| NET-8 | IDNInternetAddress.java:47-50 | L | Regex caps segments at 64 chars; valid longer addresses silently returned unencoded | code |
| NET-9 | IDNInternetAddress.java:73-111 | L | `matcher.groupCount()` conditions constant-true (dead) | remove |
| SSL-1 | KeyStoreProvider.java:186 | M | Embedded keystore loaded with provider `storePassword`, contradicting documented `keyPassword`-is-store-password contract | code |
| SSL-2 | KeyStoreProvider.java:118-122 | L | Doc says location ignored when keys present, but readability check runs unconditionally; `@return` omits empty case | code+doc |
| SSL-3 | KeyMaterialHolder.java:35 | M | equals/hashCode exclude `keyMaterial` → holders with different certs compare equal (Set dedup loses keys) | code |
| NET-10 | IDNInternetAddressTest.java | L | Sanitizer overloads/fallback/malformed punycode untested | test |
| SSL-4 | KeyStoreProviderTest.java:107 | L | keyPassword-as-storepassword, location+keys precedence, `getKeyOrStorePassword()` untested | test |

## Cluster G — Property & reflection (PR 7)

| ID | Location | Sev | Finding | Resolution |
|----|----------|-----|---------|------------|
| PROP-1 | PropertyHolder.java:168 | H | `writeTo` rejects every primitive-typed property (`int.class.isInstance(Integer)` false) | code |
| PROP-2 | PropertyHolder.java:250-256 | M | Stray public instance `build()` (leftover hand-written builder), never called | remove |
| PROP-3 | PropertyHolder.java:44-59 | M | Class example doesn't compile and demonstrates a construction path that cannot read | doc |
| PROP-4 | PropertyHolder.java:127,157-158 | L | Wrong `@throws` (NPE vs IAE; IllegalStateException vs IAE) | doc |
| PROP-5 | PropertyHolder.java:231 | L | Indexed-only property → `getPropertyType()` null → undocumented Lombok NPE | code |
| PROP-6 | PropertyUtil.java:126-132,187-195 | M | `IllegalAccessException`/`IllegalArgumentException` silently swallowed (null read / no-op write), contradicting `@throws` contract | code |
| PROP-7 | PropertyMemberInfo.java:57 | L | `NO_IDENTITY` never produced/consumed | remove |
| PROP-8 | PropertyMemberInfo.java:80-82 | L | Dangling sentence fragment in javadoc | doc |
| REFL-1 | MoreReflection.java:77-83 | M | WeakHashMap caches defeated: values strongly reference key Class → classloader leak contradicts stated intent | code |
| REFL-2 | MoreReflection.java:428-433 | L | `catch (ClassCastException)` around unchecked cast unreachable | remove |
| REFL-3 | MoreReflection.java:410-426 | L | "KeyStoreType" copy-paste in `@return` + exception message; typo "genric" | doc/code |
| REFL-4 | MoreReflection.java:52-58 | L | Class example not valid Java | doc |
| REFL-5 | MoreReflection.java:507 | L | References nonexistent `Proxy#newProxyInstance` signature | doc |
| REFL-6 | MoreReflection.java:559 | M | Same `< 5` stack-depth guard as LOG-3 in `findCallerElement` | code |
| REFL-7 | FieldWrapper.java:82-88,132-137 | M | TOCTOU: `canAccess` outside `synchronized(field)` with shared Field → spurious failures under concurrency | code |
| REFL-8 | FieldWrapper.java:112-120 | L | Static `readValue(String, Object)` NPEs on null object though doc promises Optional.empty | code |
| REFL-9 | FieldWrapper.java:131-153 | L | `writeValue` undocumented IllegalArgumentException cases | doc |
| PROP-9 | BeanWithReadWriteProperties (test) | M | `ATTRIBUTE_NOT_ACCESSIBLE` typo ≠ actual field name; all "not accessible" tests exercise nonexistent property | test |
| PROP-10 | PropertyHolderTest.java | M | No primitive-property tests (would catch PROP-1); WRITE_ONLY read / READ_ONLY write untested | test |
| PROP-11 | ExplodingBean (test) | L | `illegalAccessException()`/`invocationTargetException()` switchers never used | test |
| REFL-10 | FieldWrapperTest.java | L | Static `readValue(String, Object)` overload untested | test |

## Cluster H — base/lang/codec/concurrent (PR 8)

| ID | Location | Sev | Finding | Resolution |
|----|----------|-----|---------|------------|
| LANG-1 | LocaleUtils.java:55 | H | Headline example `toLocale("en_GB_xxx")` documented valid but throws (variant regex requires 5-8 chars) | doc |
| LANG-2 | LocaleUtils.java:64-69 | M | Doc claims deprecated Locale ctor for lenient validation; code uses strict `Locale.Builder` | doc |
| LANG-3 | LocaleUtils.java:73,119,127 | M | `IllformedLocaleException` (not IAE) escapes for e.g. `toLocale("12")`, `toLocale("_EN_v")`; underscore path skips variant validation | code |
| LANG-4 | LocaleUtils.java:99-142 | L | Unreachable `case 1`/`default`/empty-language branches; dead `handleSinglePart` | remove |
| LANG-5 | lang/package-info.java:67 | L | Example calls nonexistent `isISO639LanguageCode` | doc |
| LANG-6 | MoreObjects.java:41 | L | `@param` says "KeyStoreType" (copy-paste) | doc |
| CODEC-1 | codec/package-info.java:52-113 | M | Examples use nonexistent `Hex.encodeToString`/static `decode`; invert `toLowerCase` semantics | doc |
| CODEC-2 | Hex.java:101,450,462,526 | L | "null → IllegalArgumentException" documented; actual NPE | doc |
| CODEC-3 | Hex.java:325,363 | L | `encodeHexString(..., boolean)` `@return` claims lower-case regardless of parameter | doc |
| CONC-1 | concurrent/package-info.java:44-56 | M | Example uses package-private ctor + nonexistent `getElapsedMilliseconds()`; "split times" claim false | doc |
| CONC-2 | RingBuffer.java:205-208 | L | `nextPowerOfTwo` overflows for capacity > 2^30 → NegativeArraySizeException | code |
| CONC-3 | RingBuffer.java:152-156 (+related) | L | Statistics docs claim "average"; components are sampleCount/p50/p95/p99 | doc |
| CONC-4 | StripedRingBuffer.java:88-121 | M | `windowSize` doc claims total across stripes but single thread uses one stripe; debug-log capacity math wrong | doc+code(log) |
| BASE-1 | Preconditions.java:236-239,329-332 | L | "elements may not be null" contradicts class doc and behavior | doc |
| CODEC-4 | HexTest.java:156-162 | L | Read-only-buffer test discards `asReadOnlyBuffer()`; copy branch uncovered | test |
| LANG-7 | LocaleUtilsTest.java:86-98 | L | No variant boundary / multi-variant / numeric-language tests | test |

## Cluster I — OpenRewrite modernizations (PR 9)

| ID | Location | Sev | Finding | Resolution |
|----|----------|-----|---------|------------|
| REW-1 | 23 files (main+test) | L | Pending OpenRewrite modernizations from the pre-commit profile (List.of/Map.of migrations, if-else-if→switch, SimplifyTestThrows) leave the working tree dirty on every `-Ppre-commit` run | code (apply) |

## Cluster J — Final cleanup (PR 10)

Verify every finding above against the merged state; remove this document.
