/**
 * Provides utilities for string manipulation, joining, splitting, and text processing.
 *
 * <h2>Overview</h2>
 * <p>
 * This package offers comprehensive string handling utilities designed for efficient
 * text processing. It provides type-safe operations with proper null handling and 
 * performance optimization.
 * </p>
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li><b>String Operations</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.string.MoreStrings} - Enhanced string utilities</li>
 *       <li>Null-safe string operations</li>
 *       <li>String formatting with '%s' and '{}' placeholders</li>
 *       <li>Common string transformations</li>
 *     </ul>
 *   </li>
 *   <li><b>String Joining</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.string.Joiner} - Flexible string joining</li>
 *       <li>{@link de.cuioss.tools.string.JoinerConfig} - Configurable joining behavior</li>
 *       <li>Customizable separators and handling of null/empty values</li>
 *     </ul>
 *   </li>
 *   <li><b>String Splitting</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.string.Splitter} - String splitting utilities</li>
 *       <li>{@link de.cuioss.tools.string.SplitterConfig} - Configurable splitting behavior</li>
 *       <li>{@link de.cuioss.tools.string.TextSplitter} - HTML-aware text content splitting</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 *
 * <h3>1. String Operations with MoreStrings</h3>
 * <pre>
 * import de.cuioss.tools.string.MoreStrings;
 * import de.cuioss.tools.logging.CuiLogger;
 *
 * private static final CuiLogger log = new CuiLogger(MyService.class);
 *
 * // Null-safe operations
 * String nullString = null;
 * String empty = MoreStrings.nullToEmpty(nullString);      // Returns ""
 * String defaulted = MoreStrings.nullToDefault(nullString, "N/A");  // Returns "N/A"
 *
 * // String formatting with logging
 * try {
 *     String result = processData("input");
 *     log.info("Processed data: %s", result);
 * } catch (Exception e) {
 *     log.error(e, "Processing failed for input: %s", "input");
 *     throw e;
 * }
 * </pre>
 *
 * <h3>2. String Joining</h3>
 * <pre>
 * import de.cuioss.tools.string.Joiner;
 *
 * // Basic joining
 * List&lt;String&gt; parts = Arrays.asList("a", "b", "c");
 * String joined = Joiner.on(",").join(parts);  // "a,b,c"
 *
 * // Advanced joining with configuration
 * String result = Joiner.on(" | ")
 *     .skipNulls()           // Skip null values
 *     .skipEmpty()           // Skip empty strings
 *     .useForNull("N/A")     // Replace nulls with "N/A"
 *     .join(Arrays.asList("a", null, "", "b"));  // "a | N/A | b"
 * </pre>
 *
 * <h3>3. String Splitting</h3>
 * <pre>
 * import de.cuioss.tools.string.Splitter;
 * import de.cuioss.tools.string.TextSplitter;
 *
 * // Basic splitting
 * List&lt;String&gt; parts = Splitter.on(",")
 *     .trimResults()
 *     .omitEmptyStrings()
 *     .splitToList("a, b,,c");  // ["a", "b", "c"]
 *
 * // HTML-aware text splitting
 * TextSplitter splitter = new TextSplitter("long.technical-id#12345");
 * String withBreaks = splitter.getTextWithEnforcedLineBreaks();
 * // Adds zero-width spaces for better HTML rendering
 * </pre>
 *
 * <h2>Migration Guide</h2>
 * <p>When migrating from other string utility libraries:</p>
 * <ul>
 *   <li><b>From Apache Commons Lang</b>
 *     <ul>
 *       <li>Replace {@code StringUtils.isEmpty()} with {@code MoreStrings.isEmpty()}</li>
 *       <li>Replace {@code StringUtils.join()} with {@code Joiner.on().join()}</li>
 *       <li>Replace {@code StringUtils.split()} with {@code Splitter.on().splitToList()}</li>
 *     </ul>
 *   </li>
 *   <li><b>From Guava</b>
 *     <ul>
 *       <li>Replace {@code Strings.nullToEmpty()} with {@code MoreStrings.nullToEmpty()}</li>
 *       <li>Replace {@code Joiner} with our {@code Joiner} (similar API)</li>
 *       <li>Replace {@code Splitter} with our {@code Splitter} (similar API)</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Always use null-safe operations from {@code MoreStrings}</li>
 *   <li>Prefer {@code lenientFormat()} over {@code String.format()}</li>
 *   <li>Use {@code TextSplitter} for HTML content to ensure proper line breaks</li>
 *   <li>Configure {@code Joiner} and {@code Splitter} instances once and reuse them</li>
 *   <li>Handle empty strings appropriately using {@code isEmpty()} or {@code isBlank()}</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.string.MoreStrings
 * @see de.cuioss.tools.string.Joiner
 * @see de.cuioss.tools.string.JoinerConfig
 * @see de.cuioss.tools.string.Splitter
 * @see de.cuioss.tools.string.SplitterConfig
 * @see de.cuioss.tools.string.TextSplitter
 * @see de.cuioss.tools.logging.CuiLogger
 */
package de.cuioss.tools.string;
