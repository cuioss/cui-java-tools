/**
 * Provides utilities for string manipulation, joining, splitting, and text processing.
 *
 * <h2>Overview</h2>
 * <p>
 * This package offers comprehensive string handling utilities designed for efficient
 * text processing.
 * It provides type-safe operations with proper null handling and performance optimization.
 * </p>
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li><b>String Operations</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.string.MoreStrings} - Enhanced string utilities</li>
 *       <li>Null-safe string operations</li>
 *       <li>String formatting with '%s' placeholders</li>
 *       <li>Common string transformations</li>
 *     </ul>
 *   </li>
 *   <li><b>String Joining</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.string.Joiner} - Flexible string joining</li>
 *       <li>{@link de.cuioss.tools.string.JoinerConfig} - Joiner configuration</li>
 *       <li>Customizable separators and handling of null values</li>
 *     </ul>
 *   </li>
 *   <li><b>String Splitting</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.string.Splitter} - String splitting utilities</li>
 *       <li>{@link de.cuioss.tools.string.SplitterConfig} - Splitter configuration</li>
 *       <li>{@link de.cuioss.tools.string.TextSplitter} - Text content splitting</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>
 * // String operations
 * String nullableString = null;
 * if (MoreStrings.isEmpty(nullableString)) {
 *     LOGGER.info("String is null or empty");
 * }
 *
 * // String formatting
 * String message = MoreStrings.lenientFormat(
 *     "Processing user %s with role %s",
 *     username, role);
 *
 * // String joining
 * List<String> elements = Arrays.asList("a", "b", null, "c");
 * String joined = Joiner.on(",")
 *     .skipNulls()
 *     .join(elements);
 * // Result: "a,b,c"
 *
 * // String splitting
 * String input = "a,b,c";
 * List<String> parts = Splitter.on(",")
 *     .trimResults()
 *     .splitToList(input);
 *
 * // Text splitting
 * String text = "Long text content...";
 * List<String> chunks = TextSplitter.splitText(text, 80);
 * </pre>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Always use null-safe string operations</li>
 *   <li>Configure string operations explicitly using builder patterns</li>
 *   <li>Use '%s' for string formatting placeholders</li>
 *   <li>Consider performance when processing large strings</li>
 *   <li>Handle empty and whitespace strings appropriately</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.string.MoreStrings
 * @see de.cuioss.tools.string.Joiner
 * @see de.cuioss.tools.string.Splitter
 * @see de.cuioss.tools.string.TextSplitter
 */
package de.cuioss.tools.string;
